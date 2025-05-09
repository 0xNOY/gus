# GUS: Git User Switcher

## 概要

GUSはGitのユーザーをターミナル単位で切り替えるためのツールです．
`user.name`と`user.email`を切り替えるだけでなく，`git pull` / `git push` 時のSSH鍵も切り替えます．

## インストール

1. [cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)をインストール
2. cargoを使ってGUSをインストール  
   ```sh
   cargo install --git https://github.com/0xNOY/gus.git
   ```
3. `.bashrc`に以下の行を追加  
   ```sh
   eval "$(gus setup)"
   ```

## 使い方

```sh
# ユーザーの追加
# gus add <id> <name> <email>
gus add noy "Naoya Takenaka" noy@mailaddr.com
# このときSSH鍵が生成されます．
# 公開鍵を次のコマンドで取得し，GitHubなどに登録してください．
gus key noy

# ユーザの切り替え
# gus set <id>
gus set noy
# ユーザはターミナル単位で切り替わります．

# 詳細はヘルプを参照してください．
gus help
```

## FAQ

#### Q) gitコマンドを実行時のGUSの利用強制を無効化したい

コンフィグファイルの `force_use_gus` を `false` にしてください．

#### Q) SSH鍵生成時のパスフレーズ最低長を変更したい

コンフィグファイルの `ssh_key_passphrase_min_length` を変更してください．