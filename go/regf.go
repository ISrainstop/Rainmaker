// csdev :: regf.go  --  Windows 注册表 hive 文件 (REGF) 只读解析器
//
// 用途: 服务端解析目标机回传的 SAM / SYSTEM hive —— 取 bootkey (SYSTEM) 与
// 用户 V 值 (SAM)。只实现解析所需的最小子集: 键树导航 / 值读取 / 类名读取。
//
// 结构说明 (每一条都用本机 `reg save` 的真实 hive 逐字段核对过, 不是抄文档):
//   - 文件头 0x1000 字节, 前 4 字节为 "regf"; 0x24 处 u32 = 根键 cell 偏移
//   - cell 的文件偏移 = 0x1000 + cell偏移; cell 数据前 4 字节是有符号长度
//     (负数 = 已分配, 取绝对值)
//   - nk 键节点 / vk 值节点 / lf|lh|li|ri 子键索引 / sk 安全描述符
//
// 实测锚点 (本机 SAM hive, ROOT 键):
//   0x1020 cell -> 0x1024 "nk"; 0x14=1 子键数; 0x1C=0x2C0 子键列表;
//   0x24=0 值数量; 0x28=0xFFFFFFFF 无值列表; 0x30=0xFFFFFFFF 无类名;
//   0x48=4 名长; 0x4C="ROOT"
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

const (
	regfHeaderSize = 0x1000 // regf 头固定 0x1000 字节
	// 畸形 hive 防御: 单个键最多接受这么多子键 / 值
	regfMaxChildren = 1 << 16
	regfMaxRILayers = 4
)

// Hive 是一个已加载的注册表 hive 文件 (只读)
type Hive struct {
	b []byte
}

// RegKey 是 nk 键节点
type RegKey struct {
	h            *Hive
	off          uint32 // cell 偏移 (相对 hbin 数据区)
	Name         string
	Flags        uint16
	SubKeyCount  uint32
	ValueCount   uint32
	subListOff   uint32
	valueListOff uint32
	classOff     uint32
	classNameLen uint16
}

// RegValue 是 vk 值节点
type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

// ---------------------------------------------------------------- 加载

// ParseHive 解析内存中的 hive 字节流
func ParseHive(b []byte) (*Hive, error) {
	if len(b) < regfHeaderSize {
		return nil, fmt.Errorf("hive 过短: %d 字节 (至少需要 %d)", len(b), regfHeaderSize)
	}
	if string(b[0:4]) != "regf" {
		return nil, fmt.Errorf("不是注册表 hive: 文件头为 %q, 期望 \"regf\"", string(b[0:4]))
	}
	// 序列号一致性: 主/次序号不等说明文件是脏的 (未正常卸载)
	if binary.LittleEndian.Uint32(b[4:8]) != binary.LittleEndian.Uint32(b[8:12]) {
		// 不致命: reg save 产物偶有差异, 仅记录
		_ = b
	}
	return &Hive{b: b}, nil
}

// LoadHiveFile 从磁盘读取并解析 hive
func LoadHiveFile(path string) (*Hive, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseHive(b)
}

// ---------------------------------------------------------------- cell

// cellData 返回 cell 的数据部分 (跳过开头 4 字节长度字段)。
// 返回值直接指向底层数组, 调用方不得修改。
func (h *Hive) cellData(off uint32) ([]byte, error) {
	// off == 0xFFFFFFFF 是"无"的约定值
	if off == 0xFFFFFFFF {
		return nil, fmt.Errorf("cell 偏移为 -1 (无)")
	}
	abs := regfHeaderSize + int(off)
	if abs < regfHeaderSize || abs+4 > len(h.b) {
		return nil, fmt.Errorf("cell 偏移越界: 0x%X", off)
	}
	size := int32(binary.LittleEndian.Uint32(h.b[abs : abs+4]))
	if size < 0 {
		size = -size
	}
	if size < 4 || abs+int(size) > len(h.b) {
		return nil, fmt.Errorf("cell 长度非法: off=0x%X size=%d", off, size)
	}
	return h.b[abs+4 : abs+int(size)], nil
}

// ---------------------------------------------------------------- 键

// Root 返回 hive 根键
func (h *Hive) Root() (*RegKey, error) {
	return h.key(binary.LittleEndian.Uint32(h.b[0x24:0x28]))
}

// key 按 cell 偏移解析一个 nk 节点
func (h *Hive) key(off uint32) (*RegKey, error) {
	d, err := h.cellData(off)
	if err != nil {
		return nil, err
	}
	if len(d) < 0x4C {
		return nil, fmt.Errorf("nk 节点过短: %d 字节", len(d))
	}
	if string(d[0:2]) != "nk" {
		return nil, fmt.Errorf("期望 nk 节点, 实际为 %q", string(d[0:2]))
	}
	k := &RegKey{
		h:            h,
		off:          off,
		Flags:        binary.LittleEndian.Uint16(d[2:4]),
		SubKeyCount:  binary.LittleEndian.Uint32(d[0x14:0x18]),
		ValueCount:   binary.LittleEndian.Uint32(d[0x24:0x28]),
		subListOff:   binary.LittleEndian.Uint32(d[0x1C:0x20]),
		valueListOff: binary.LittleEndian.Uint32(d[0x28:0x2C]),
		classOff:     binary.LittleEndian.Uint32(d[0x30:0x34]),
		classNameLen: binary.LittleEndian.Uint16(d[0x4A:0x4C]),
	}
	nameLen := int(binary.LittleEndian.Uint16(d[0x48:0x4A]))
	if nameLen > len(d)-0x4C {
		nameLen = len(d) - 0x4C
	}
	raw := d[0x4C : 0x4C+nameLen]
	// KEY_COMP_NAME (0x20) 置位 = 名字是单字节 (Latin-1) 而非 UTF-16LE
	if k.Flags&0x0020 != 0 {
		k.Name = string(raw)
	} else {
		k.Name = decodeUTF16LE(raw)
	}
	return k, nil
}

// SubKey 按名字取子键 (Windows 注册表键名大小写不敏感)
func (k *RegKey) SubKey(name string) (*RegKey, error) {
	subs, err := k.SubKeys()
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		if strings.EqualFold(s.Name, name) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("键 %s 下没有子键 %q", k.Name, name)
}

// SubKeys 列举全部子键 (展开 lf/lh/li/ri 索引)
func (k *RegKey) SubKeys() ([]*RegKey, error) {
	if k.subListOff == 0xFFFFFFFF || k.subListOff == 0 {
		return nil, nil
	}
	offs, err := k.h.collectSubKeyOffsets(k.subListOff, 0)
	if err != nil {
		return nil, err
	}
	out := make([]*RegKey, 0, len(offs))
	for _, o := range offs {
		c, err := k.h.key(o)
		if err != nil {
			continue // 跳过损坏项, 不让单个坏节点毁掉整个枚举
		}
		out = append(out, c)
	}
	return out, nil
}

// collectSubKeyOffsets 展开子键索引列表, 返回其中的 nk cell 偏移
func (h *Hive) collectSubKeyOffsets(listOff uint32, depth int) ([]uint32, error) {
	if depth > regfMaxRILayers {
		return nil, fmt.Errorf("子键索引嵌套过深 (>%d)", regfMaxRILayers)
	}
	d, err := h.cellData(listOff)
	if err != nil {
		return nil, err
	}
	if len(d) < 4 {
		return nil, fmt.Errorf("子键列表过短")
	}
	sig := string(d[0:2])
	count := int(binary.LittleEndian.Uint16(d[2:4]))
	if count > regfMaxChildren {
		return nil, fmt.Errorf("子键列表项数异常: %d", count)
	}

	switch sig {
	case "lf", "lh":
		// [2B sig][2B count][count × (4B nk偏移 + 4B 名字hash)]
		if len(d) < 4+count*8 {
			return nil, fmt.Errorf("lf/lh 列表截断")
		}
		out := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, binary.LittleEndian.Uint32(d[4+i*8:4+i*8+4]))
		}
		return out, nil
	case "li":
		// [2B sig][2B count][count × 4B nk偏移]
		if len(d) < 4+count*4 {
			return nil, fmt.Errorf("li 列表截断")
		}
		out := make([]uint32, 0, count)
		for i := 0; i < count; i++ {
			out = append(out, binary.LittleEndian.Uint32(d[4+i*4:4+i*4+4]))
		}
		return out, nil
	case "ri":
		// [2B sig][2B count][count × 4B 子列表偏移], 需要递归展开
		if len(d) < 4+count*4 {
			return nil, fmt.Errorf("ri 列表截断")
		}
		var out []uint32
		for i := 0; i < count; i++ {
			sub := binary.LittleEndian.Uint32(d[4+i*4 : 4+i*4+4])
			more, err := h.collectSubKeyOffsets(sub, depth+1)
			if err != nil {
				continue
			}
			out = append(out, more...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("未知子键列表签名 %q", sig)
}

// ---------------------------------------------------------------- 值

// Value 按名字取值 (大小写不敏感)
func (k *RegKey) Value(name string) (*RegValue, error) {
	vals, err := k.Values()
	if err != nil {
		return nil, err
	}
	for _, v := range vals {
		if strings.EqualFold(v.Name, name) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("键 %s 下没有值 %q", k.Name, name)
}

// Values 列举全部值
func (k *RegKey) Values() ([]*RegValue, error) {
	n := int(k.ValueCount)
	if n <= 0 || k.valueListOff == 0xFFFFFFFF || k.valueListOff == 0 {
		return nil, nil
	}
	if n > regfMaxChildren {
		return nil, fmt.Errorf("值数量异常: %d", n)
	}
	list, err := k.h.cellData(k.valueListOff)
	if err != nil {
		return nil, err
	}
	if len(list) < n*4 {
		return nil, fmt.Errorf("值列表截断: 需要 %d 字节, 只有 %d", n*4, len(list))
	}
	out := make([]*RegValue, 0, n)
	for i := 0; i < n; i++ {
		vkOff := binary.LittleEndian.Uint32(list[i*4 : i*4+4])
		v, err := k.h.value(vkOff)
		if err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// value 解析一个 vk 节点
func (h *Hive) value(off uint32) (*RegValue, error) {
	d, err := h.cellData(off)
	if err != nil {
		return nil, err
	}
	if len(d) < 0x14 {
		return nil, fmt.Errorf("vk 节点过短: %d 字节", len(d))
	}
	if string(d[0:2]) != "vk" {
		return nil, fmt.Errorf("期望 vk 节点, 实际为 %q", string(d[0:2]))
	}
	nameLen := int(binary.LittleEndian.Uint16(d[2:4]))
	raw := int64(binary.LittleEndian.Uint32(d[4:8]))
	t := binary.LittleEndian.Uint32(d[0x0C:0x10])

	name := ""
	if nl := len(d) - 0x14; nl > 0 {
		if nameLen > nl {
			nameLen = nl
		}
		nb := d[0x14 : 0x14+nameLen]
		if t == 0 && len(nb) > 0 { // 类型未知时按单字节处理
			name = string(nb)
		} else {
			name = string(nb)
		}
	}

	v := &RegValue{Name: name, Type: t}

	const inlineFlag = 0x80000000
	if raw&inlineFlag != 0 {
		// 数据内联在 data offset 字段 (最多 4 字节)
		n := int(raw & 0x7FFFFFFF)
		if n > 4 {
			n = 4
		}
		v.Data = append([]byte(nil), d[8:8+n]...)
		return v, nil
	}

	dataLen := int(raw & 0x7FFFFFFF)
	if dataLen == 0 {
		return v, nil
	}
	if dataLen < 0 || dataLen > h.maxValueSize() {
		return nil, fmt.Errorf("值数据长度异常: %d", dataLen)
	}
	dataOff := binary.LittleEndian.Uint32(d[8:12])
	blob, err := h.cellData(dataOff)
	if err != nil {
		return nil, err
	}
	if dataLen > len(blob) {
		dataLen = len(blob)
	}
	v.Data = append([]byte(nil), blob[:dataLen]...)
	return v, nil
}

func (h *Hive) maxValueSize() int {
	if len(h.b) > regfHeaderSize {
		return len(h.b) - regfHeaderSize
	}
	return 0
}

// ClassName 返回键的类名 (bootkey 就是从 LSA 四个子键的类名取的)
// 注意: 类名以 UTF-16LE 存储, 这里解码为字符串
func (k *RegKey) ClassName() string {
	if k.classOff == 0xFFFFFFFF || k.classOff == 0 || k.classNameLen == 0 {
		return ""
	}
	d, err := k.h.cellData(k.classOff)
	if err != nil {
		return ""
	}
	n := int(k.classNameLen)
	if n > len(d) {
		n = len(d)
	}
	return decodeUTF16LE(d[:n])
}

// ---------------------------------------------------------------- 工具

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}
