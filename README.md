# GUS: Git User Switcher

## 概要

GUSはGitのユーザーを切り替えるためのツールです。
`user.name`と`user.email`を切り替えるだけでなく、sshの鍵も切り替えます。

## インストール

まず、[cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)をインストールしてください。

次に、cargoを使ってGUSをインストールします。
```sh
cargo install --git https://github.com/0xNOY/gus.git
```

最後に、`.bashrc`に以下の行を追加してください。
```sh
eval "$(gus setup)"
```

## 使い方

```sh
# ユーザーの追加
# gus add <id> <name> <email>
gus add noy "Naoya Takenaka" noy@mailaddr.com
# このとき、SSHの鍵が作成されます。
# 公開鍵を次のコマンドで取得し、GitHubなどに登録してください。
gus key noy

# ユーザの切り替え
# gus set <id>
gus set noy
# ユーザはターミナル単位で切り替わります。

# 詳細はヘルプを参照してください。
gus help
```