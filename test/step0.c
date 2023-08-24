#include "util.h"
#include "test.h"

int
main(void)
{
    // デバッグ用関数
    debugf("Hello, World!");

    // 16進ダンプを出力
    // 使用する場合は、`CFLAGS=-DHEXDUMP` をつけて `make` する
    debugdump(test_data, sizeof(test_data));

    return 0;
}
