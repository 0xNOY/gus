# GUS: Git User Switcher

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 概要

GUSは、複数のGitアカウント（例：個人用、仕事用）を簡単に切り替えるためのコマンドラインツールです。
ターミナルセッションごとに異なるGitユーザー設定を管理し、SSH鍵の自動切り替えもサポートします。

### 主な機能

- 🔄 ターミナルセッション単位でのGitユーザー切り替え
- 🔑 SSH鍵の自動生成と管理
- 📁 ディレクトリベースの自動ユーザー切り替え
- ⚠️ Gitコマンド実行時のユーザ選択強制

## インストール

### 前提条件

- Rust と Cargo（[インストール方法](https://doc.rust-lang.org/cargo/getting-started/installation.html)）
- Git

### インストール手順

1. Cargoを使用してインストール:
   ```sh
   cargo install --git https://github.com/0xNOY/gus.git
   ```

2. シェル設定の追加（`.bashrc`、`.zshrc`など）:
   ```sh
   eval "$(gus setup)"
   ```

## 基本的な使い方

### ユーザーの追加

```sh
# 基本形式: gus add <id> <name> <email>
gus add work "Work Name" work@example.com
gus add personal "Personal Name" personal@example.com
```

- 初回実行時にSSH鍵が自動生成されます
- 生成された公開鍵を取得:
  ```sh
  gus key work  # 公開鍵を表示
  ```

### ユーザーの切り替え

```sh
# 基本形式: gus set <id>
gus set work     # 仕事用アカウントに切り替え
gus set personal # 個人用アカウントに切り替え
```

### 現在のユーザー確認

```sh
gus current  # 現在のユーザー情報を表示
```

### ユーザー一覧の表示

```sh
gus list           # テーブル形式で表示
gus list --simple  # シンプルな形式で表示
```

## 高度な機能

### 自動切り替え機能

特定のディレクトリに移動した際に、自動的にGitユーザーを切り替えることができます。

```sh
# 自動切り替えの有効化
gus auto-switch enable

# パターンの追加
gus auto-switch add "~/work/*" work
gus auto-switch add "~/personal/*" personal

# パターンの一覧表示
gus auto-switch list

# パターンの削除
gus auto-switch remove "~/work/*"

# 自動切り替えの無効化
gus auto-switch disable
```

### パターンの例

- `~/work/*` - 仕事用ディレクトリ
- `~/personal/*` - 個人用ディレクトリ
- `**/github.com/company/*` - 会社のGitHubリポジトリ
- `~/{work,company}/*` - 複数ディレクトリの指定

## 設定

設定ファイルは `~/.config/gus/config.toml` に保存されます。

```toml
# デフォルト設定
default_sshkey_dir = "~/.ssh"
default_sshkey_type = "ed25519"
default_sshkey_rounds = 100
min_sshkey_passphrase_length = 10
force_use_gus = true
auto_switch_enabled = false

# 自動切り替えパターン
[[auto_switch_patterns]]
pattern = "~/work/*"
user_id = "work"

[[auto_switch_patterns]]
pattern = "~/personal/*"
user_id = "personal"
```

## コマンドリファレンス

### 基本コマンド

| コマンド | 説明 |
|----------|------|
| `gus add <id> <name> <email>` | 新しいユーザーを追加 |
| `gus remove <id>` | ユーザーを削除 |
| `gus set <id>` | 指定したユーザーに切り替え |
| `gus current` | 現在のユーザーを表示 |
| `gus list` | ユーザー一覧を表示 |
| `gus key <id>` | 指定したユーザーの公開鍵を表示 |

### 自動切り替えコマンド

| コマンド | 説明 |
|----------|------|
| `gus auto-switch enable` | 自動切り替えを有効化 |
| `gus auto-switch disable` | 自動切り替えを無効化 |
| `gus auto-switch add <pattern> <user_id>` | 自動切り替えパターンを追加 |
| `gus auto-switch remove <pattern>` | 自動切り替えパターンを削除 |
| `gus auto-switch list` | 自動切り替えパターンを一覧表示 |
| `gus auto-switch check` | 現在のディレクトリで自動切り替えを確認 |

## トラブルシューティング

### よくある質問

#### Q) Gitコマンド実行時のGUSの利用強制を無効化したい

設定ファイルの `force_use_gus` を `false` に設定してください。

#### Q) SSH鍵生成時のパスフレーズ最低長を変更したい

設定ファイルの `min_sshkey_passphrase_length` を変更してください。

## 貢献

1. このリポジトリをフォーク
2. 新しいブランチを作成 (`git checkout -b feature/amazing-feature`)
3. 変更をコミット (`git commit -m 'Add some amazing feature'`)
4. ブランチにプッシュ (`git push origin feature/amazing-feature`)
5. プルリクエストを作成

## ライセンス

このプロジェクトはMITライセンスの下で公開されています。詳細は[LICENSE](LICENSE)ファイルを参照してください。