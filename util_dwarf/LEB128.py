from typing import List


class ULEB128:
    """
    unsigned LEB128 parse class
    """

    def __init__(self, values: List[int]) -> None:
        """
        @value 1バイトデータ列
        """
        # 初期化
        # ULEB128値
        self.value = 0
        # ULEB128構成bit長
        self.len_bit = 0
        self.len_byte = 0

        if isinstance(values, int):
            self.value = values
            self.len_bit = 8
            self.len_byte = 1
        elif isinstance(values, list):
            # 解析
            for n_th, value in enumerate(values):
                self.len_bit += 7
                # 7bit目(0開始)をチェック
                # bit演算より四則演算の方が速いらしい
                if value / 0x80 >= 1:
                    self.value += (value % 0x80) * (2 ** (7 * (n_th)))
                else:
                    self.value += value * (2 ** (7 * (n_th)))
            # バイト長計算
            self.len_byte = int((self.len_bit + 7) / 8)
        else:
            raise Exception("invalid ULEB128 input: " + str(values))


class SLEB128:
    """
    signed LEB128 parse class
    """

    def __init__(self, values: List[int]) -> None:
        # 初期化
        self.value = 0

        # ULEB128でデータ解析
        uleb128 = ULEB128(values)
        self.len_byte = uleb128.len_byte
        # ULEB128の値の符号の位置を算出
        sign_bit = 2 ** (7 * uleb128.len_byte - 1)
        # ULEB128値の符号位置をチェック
        if uleb128.value & sign_bit != 0:
            # 符号付きデータ
            # 符号ビットより上位bitをマスクするデータを作成
            mask_bit = (2 ** (8 * uleb128.len_byte)) - ((2 ** (7 * uleb128.len_byte)) - 1) - 1
            # マスクをかける
            value = uleb128.value + mask_bit
            # LEB128で表現されているバイト数分だけをバイトシーケンスとして抽出
            # 抽出したバイトシーケンスをsigned整数として解析して値に変換
            buff = []
            for i in range(0, self.len_byte):
                buff.append(int(value % 256))
                value = int(value / 256)
            self.value = int.from_bytes(bytearray(buff), "little", signed=True)
        else:
            # 符号なしデータ
            self.value = uleb128.value


"""
# -129
sleb = SLEB128([255, 126])
pass
# 129
sleb = SLEB128([129, 1])
pass
# -2
sleb = SLEB128([126])
pass
# 2
sleb = SLEB128([2])
pass
# -344865
sleb = SLEB128([0xDF, 0xF9, 0x6A])
pass
"""
