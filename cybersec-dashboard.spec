# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['dashboard/app.py'],
    pathex=['.'],
    binaries=[],
    datas=[('dashboard/templates', 'dashboard/templates'), ('config.yaml', '.'), ('ml_anomaly_model.joblib', '.'), ('*.py', '.')],
    hiddenimports=['sklearn.ensemble._forest', 'sklearn.tree._classes', 'sklearn.utils._typedefs', 'sklearn.neighbors._partition_nodes', 'flask', 'flask_limiter', 'requests', 'sqlite3'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cybersec-dashboard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
