import json
from src.ai_cyber_helper import AiCyberHelper


def test_save_config_persists(tmp_path):
    cfg = {"vuln_scan": {"scan_safe_mode": True, "allow_public_targets": False}}
    cfg_path = tmp_path / 'cfg.json'
    cfg_path.write_text(json.dumps(cfg))

    helper = AiCyberHelper(config_path=str(cfg_path))
    assert helper.config.get('vuln_scan', {}).get('allow_public_targets') is False

    helper.config.setdefault('vuln_scan', {})['allow_public_targets'] = True
    saved = helper.save_config()
    assert saved is True

    # Re-load and verify
    helper2 = AiCyberHelper(config_path=str(cfg_path))
    assert helper2.config.get('vuln_scan', {}).get('allow_public_targets') is True