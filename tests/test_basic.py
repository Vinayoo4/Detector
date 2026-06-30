def test_import():
    from app import create_app
    app = create_app()
    assert app is not None
