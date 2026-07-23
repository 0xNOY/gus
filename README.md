# GUS: Git User Switcher

GUS は、同じ OS アカウントと Git リポジトリを複数人で利用するときに、別セッションの Git identity を誤って使う事故を防ぐためのツールです。

現在はプレビュー版です。Linux、macOS、FreeBSD 向けのネイティブ Git シムと、ターミナルセッション単位のユーザー選択を実装しています。Windows と VS Code 統合は開発中です。

## 現在利用できる機能

- `.bashrc` や `.zshrc` を書き換えないネイティブ Git シム
- commit など identity が必要な操作までユーザー選択を遅延
- controlling TTY ごとに独立したユーザー選択
- author / committer 情報の明示的な注入
- 非対話環境で未選択の保護対象操作を拒否
- identity が不要な Git 操作を選択なしで実行
- Linux、macOS、FreeBSD での検証済み system Git 起動

SSH 鍵、HTTP credential、VS Code の自動導入、Windows 用シムはまだ利用者向けに完成していません。

## インストール

Rust 1.85 以降と Git が必要です。

```sh
cargo install --git https://github.com/0xNOY/gus.git gus-shim --locked --force
gus setup
gus doctor
```

`gus setup` は GUS のインストール先に `git` シムを配置します。そのディレクトリが既存の実 Git より前の `PATH` にない場合は、安全に透過置換できないため失敗します。Shell コードの `eval` や rc ファイルの変更は行いません。

既に起動している Shell や IDE が以前の Git path を保持している場合は、一度だけ再起動してください。

## ユーザーを登録する

```sh
gus user add work "Work Name" work@example.com
gus user add personal "Personal Name" personal@example.com
gus user list
```

プロフィールは既定で `~/.config/gus/profiles.toml` に保存されます。`XDG_CONFIG_HOME` が設定されている場合は `$XDG_CONFIG_HOME/gus/profiles.toml` を使います。

登録を削除するには次を実行します。

```sh
gus user remove personal
```

## Git を使う

通常どおり `git` を実行します。

```sh
git status
git commit -m "message"
```

`git status` のように identity が不要な操作では選択を求めません。commit などで初めて identity が必要になると、controlling TTY にプロフィール一覧を表示します。選択結果はそのターミナルセッションだけで再利用され、別のターミナルへ暗黙に引き継がれません。

TTY のない非対話環境では、未選択の保護対象操作を拒否します。自動化でプロフィールを明示する場合は、実行単位で `GUS_PROFILE_ID` を渡せます。

```sh
GUS_PROFILE_ID=work git commit -m "automated change"
```

この環境変数を共有 Shell の常設設定に入れないでください。セッション分離を迂回するため、対象プロセスだけに渡します。

## 診断とアンインストール

```sh
gus doctor
gus uninstall-shim
```

`gus doctor` は現在 `PATH` 上で選ばれるシムの所有情報と内容を検証します。`gus uninstall-shim` は GUS が所有し、変更されていないことを確認できたシムだけを削除します。

## 開発

```sh
cargo test --workspace
npm --prefix editors/vscode test
```

プラットフォーム固有のテストは GitHub Actions でも実行します。

## ライセンス

[MIT License](LICENSE)
