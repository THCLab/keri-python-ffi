from libs.libkel_utils import Entity
import tempfile
# ==========================================
# Eve
# ==========================================

eve_temp_dir = tempfile.TemporaryDirectory()
temp_provider = "./adr_db"
seeds = "[\"rwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc=\", \"6zz7M08-HQSFq92sJ8KJOT2cZ47x7pXFQLPB0pckB3Q=\"]"
eve = Entity.new(eve_temp_dir.name, 'localhost:5621', seeds, temp_provider)
print("\nEve's prefix " + eve.get_prefix())

eve.run()