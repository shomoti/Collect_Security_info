# CTI Collector

セキュリティ技術インテリジェンスの収集・整形パイプライン:
RSS収集 -> LLM要約/タグ付け/スコアリング/Sigma生成 -> Jira Intel/Validation チケット化

## 機能
- RSS allowlist に基づく収集
- `trafilatura` を用いた本文抽出（失敗時は要約テキストへフォールバック）
- OpenAI互換ローカルLLM連携（`/v1/chat/completions`）
- 厳格な出力検証（必須項目、タグallowlist、Sigma必須キー）
- Jira Cloud REST v3 連携
- SQLite + URL正規化 + 任意の Jira JQL フォールバックによる冪等処理
- 既存Intel課題の更新戦略（`source_url` / `cve` / タイトル+本文類似）
- IOC抽出・正規化（LLM出力と本文正規表現抽出のマージ）
- `impact_score` と独立した `confidence_score` 算出
- Sigma品質ゲート（`drop_invalid_rules`、backend適合性チェック）
- JSON構造化ログと実行サマリー

## プロジェクト構成
- `src/cti_collector/config.py`: 設定ファイル・タグ辞書の読み込み
- `src/cti_collector/rss.py`: RSS取得と本文抽出
- `src/cti_collector/llm.py`: LLMクライアントとJSON復旧
- `src/cti_collector/models.py`: 出力検証とSigmaゲート
- `src/cti_collector/jira.py`: Jira課題作成・リンク・検索
- `src/cti_collector/storage.py`: SQLiteベースの冪等管理
- `src/cti_collector/pipeline.py`: エンドツーエンド処理
- `scripts/run_daily.py`: 日次実行エントリポイント

## セットアップ
1. 依存パッケージをインストール
```bash
pip install -r requirements.txt
```
2. 実行用設定ファイルを作成
```bash
cp config.example.yaml config.yaml
```
3. 環境変数を設定
```bash
export JIRA_EMAIL="you@example.com"
export JIRA_API_TOKEN="..."
export LLM_API_KEY="..."
```
（Windows PowerShell）
```powershell
$env:JIRA_EMAIL="you@example.com"
$env:JIRA_API_TOKEN="..."
$env:LLM_API_KEY="..."
```

## 実行
```bash
python scripts/run_daily.py --config config.yaml --tags tag_dictionary.yaml --prompt prompts/system_prompt.txt
```

## Jira側の前提設定
- `config.yaml` の `jira.fields.intel.confidence_score` に対応するカスタムフィールドを用意してください。
- `source_url` と `cve_list` は Jira 上で検索可能な状態にしてください（更新マッチングに使用）。
- Intel/Validation の課題タイプ名とカスタムフィールドIDは、対象プロジェクトの画面/コンテキストと一致させてください。

## 追加された設定項目（最新）
最新の `config.example.yaml` では、以下の項目が追加されています。
- `update_strategy`: 既存課題更新の挙動
- `ioc`: 正規表現抽出、重複排除、種別ごとの最大件数
- `confidence_scoring`: confidence算出の重み調整
- `feedback_learning`: アナリスト判定（useful/noise）をもとにソース別confidence補正を学習
- `sigma.drop_invalid_rules`, `sigma.target_backends`: Sigma品質ゲートの挙動
- `jira.fields.intel.confidence_score`: confidenceスコアのJiraマッピング

## 出力スキーマの追加項目
- LLM/パイプライン出力に `confidence_score` と `confidence_factors` が追加されます。
- IOCは固定キーで正規化されます: `ips`, `domains`, `urls`, `hashes`, `emails`, `files`, `registry`, `mutexes`。

## 注意事項
- Priority/Status更新は対象外です（Jira Automationでの運用を想定）。
- MISP連携はMVP範囲外です。
- Sigma実行時検証では `title`, `logsource`, `detection`, `condition` を必須キーとして確認します。
- `sigma.drop_invalid_rules=true` の場合、無効なSigmaルールはJira連携前に除外されます。

## アナリストフィードバック学習（任意）
- `feedback_learning.enable=true` の場合、更新対象Intel課題から `feedback_learning.verdict_field_id` の値を読み取り、`state.db` 内部に判定を蓄積します。
- 判定値は `useful_values` / `noise_values` で正規化され、ソース単位の集計結果から `confidence_score` に補正値（`analyst_feedback_bias`）を加算します。
- 補正は `min_events` 件以上のデータがあるソースのみ対象です。過学習防止のため、補正幅は `max_abs_source_weight` でクリップされます。
