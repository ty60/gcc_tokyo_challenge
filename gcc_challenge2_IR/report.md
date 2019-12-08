# Incident response report
以下と同じレポートが次の URL からも確認できる https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge2_IR/report.md

# 問1
## 1.
- 修正箇所のオフセット: 0x0
- 修正内容: オフセット 0x4000 のブロック (0x1000 Bytes) をオフセット 0x0 にコピーする
## 2.
与えられた `challenge.raw` の先頭の container superblock はいくつかの値が改ざんされているためそのままではマウントできない。  
具体的には `nx_magic` が `XXXX` に、 `nx_block_size` が `0x00001000` に、そして `nx_omap_id` が `0x00000000` に書き換えられていた。  
なので checkpoint descriptor area に保存されている container superblock のバックアップの中から最新のバックアップ (最大の `o_xid` を持つブロック) を`challenge.raw` から探すとオフセット 0x4000 に存在することが確認できた。  
この最新の container superblock のバックアップをオフセット 0x0 にコピーすることで `challegen.raw` がマウントできるようになる。

# 問2
## 1.
1. オフセット 0x0 に オフセット 0x8000 のブロック (container superblock のバックアップ, o_xid == 0x3c) をコピーする
2. オフセット 0x2000 にあるオブジェクト (container superblock のバックアップ, o_xid == 0x3d) の先頭 8 bytes にあるチェックサム を 0xff で上書きする
3. オフセット 0x4000 にあるオブジェクト (container superblock のバックアップ, o_xid == 0x3e) の先頭 8 bytes にあるチェックサム を 0xff で上書きする
## 2.
問1で `challenge.raw` を修正しても `root/IIR/iir_vol40.pdf` が正常に読み込めなかった。これは問1で container の先頭にコピーした最新の container superblock のバックアップが利用している volume の `iir_vol40.pdf` への参照情報 (`j_file_extent_val_t`) が破壊されているからである。

オフセット 0x8000 には container superblock の最新ではないバックアップが保存されている (o_xid == 0x3c) 。このバックアップが利用している volume の `iir_vol40.pdf` への参照情報は破壊されていない。なのでこのバックアップを container superblock として container 先頭の オフセット 0x0 にコピーした。

ただこれだけでは apfs-fuse でマウントしたとしても `irr_vol40.pdf` は正常に読み込めない。配布資料 `apfs101.pdf` の p10 には apfs-fuse は checkpoint descriptor area にある最新世代の container superblock を利用しないとあるが、おそらく実際には apfs-fuse にこのような機能が実装されていると考えられる (https://github.com/sgan81/apfs-fuse/blob/a04abfed5801934b7fa4029116b6738f5f2a3814/ApfsLib/ApfsContainer.cpp#L85)。

このため `iir_vol40.pdf` の正常な情報を保持している container superblock を container 先頭にコピーして apfs-fuse でマウントしただけではファイルは読み込めない。apfs-fuse はより新しい世代の、 `iir_vol40.pdf` の情報が壊れている container superblock のバックアップを探し出して利用するからである。  
具体的には先頭にコピーしたバックアップ (o_xid == 0x3c) よりも新しいバックアップが2つある。1つはオフセット 0x2000 (o_xid == 0x3d)、もう一つはオフセット 0x4000 (o_xid == 0x3e) に存在するバックアップである。  
今回はこれら2つのバックアップオブジェクトのチェックサムに正しくないチェックサム値を上書きすることにした。チェックサムが正しくなければそれらのバックアップは無視されることとなり、先頭にコピーした o_xid == 0x3c が最新の container superblock として利用される。  

最初にオフセット 0x0 にコピーした o_xid == 0x3c の container superblock は正しい `iir_vol40.pdf` の情報を持つ volume を参照している。なので不要なバックアップのチェックサムを破壊した後 apfs-fuse でマウントすると `sample.raw` 中の `iir_vol40.pdf` と同じ MD5 ハッシュ値を持つ `iir_vol40.pdf` が読み取れた。

## 3.
以下に調査内容を記す。
まず問1で修正した `challenge.raw` をマウントして `iir_vol40.pdf` を確認するとファイルサイズは `sample.raw` の `iir_vol40.pdf` と同じにも関わらず、内容が全て 0x00 で埋め尽くされていることが確認できた。  
ファイルが存在しているということ、そして内容は破壊されているが、サイズは正常なものと同じなので container や volume は正常だがファイルへの参照情報が壊れているのではないかと考えた。

修正後の `challege.raw` の内容を `apfs-dump` を用いて確認した。すると container superblock から利用されている filesystem object が paddr 0x12D にあることが分かった。この object を見ると `iir_vol40.pdf` の file extent value の内 `phys_block_num` が 0x00 で上書きされていることが判明した。

また同様の `apfs-dump` から checkpoint descriptor area にある複数の container superblock のバックアップの内 o_xid == 0x3c は正しい `iir_vol40.pdf` への参照情報を保持する volume を利用していることが分かった。  
なのでこのバックアップを先頭にコピーすれば正常に `iir_vol40.pdf` が読み取れると考え、実際にコピーしてマウントしたが、正常に読み取ることができなかった。

ここで `apfs-fuse` をデバッグモードで起動すると `Found more recent xid 62 than superblock 0 contained (60).` というメッセージが表示された。  
このメッセージより、先頭に移動した o_xid == 0x3c の container superblock よりも新しいバックアップ (o_xid == 0x3e) が checkpoint descriptor area から探索され、利用されてしまっていることが分かった。 o_xid == 0x3c よりも新しいバックアップは既に `iir_vol40.pdf` の情報が壊れてしまっている。このためなんとかして apfs-fuse に壊れているバックアップを無視し、 o_xid == 0x3c の container superblock を利用してもらわなければならない。

今回は o_xid == 0x3c よりも新しいバックアップのチェックサムを破壊することで対応した。チェックサムが間違っているバックアップを apfs-fuse は無視するので、無視してほしいバックアップのチェックサムを破壊することで o_xid == 0x3c の container superblock が利用され、 `iir_vol40.pdf` が正常に読み取れた。

一連の作業を行うプログラムを作成し、修正を行った。
ソースコードは次から確認できる: https://github.com/yasm1/gcc_tokyo_challenge/blob/master/gcc_challenge2_IR/src/revert_old_superblock.c
