"""Demos of `source-coop product`, against demo/stub.py's fixtures:

    python3 -I demo/record.py demo/demos/products.py [NAME ...]

DOWN, UP, RIGHT, LEFT, ESC and BACKSPACE are given by record.py.
"""


def list_products(s):
    s.run("source-coop product list demo-org --format table")
    s.prompt()
    s.run("source-coop product list demo-org --json | jq -c '.[] | {product_id, visibility}'")


def view(s):
    s.run("source-coop product view demo-org/climate-grid")


def create(s):
    s.run("source-coop product create")
    s.see("Account")
    s.key(DOWN)
    s.enter()
    s.see("Product ID")
    s.type("sea-ice")
    s.enter()
    s.see("Title")
    s.enter()
    s.see("Description")
    s.type("Weekly Arctic sea ice extent.")
    s.enter()
    s.see("Data connection")
    s.enter()
    s.see("Visibility")
    s.key(DOWN)
    s.enter()
    s.see("Create this product")
    s.pause(3)
    s.enter()


def browse(s):
    s.run("source-coop product list demo-org -i")
    s.see("Products")
    s.pause(1)
    s.key(DOWN)
    s.key(RIGHT)
    s.see("Visibility")
    s.pause(3)
    s.key(LEFT)
    s.see("Products")
    s.pause(1)
    s.key("q")


DEMOS = {
    "product-list": ("source-coop product list", list_products),
    "product-view": ("source-coop product view", view),
    "product-create": ("source-coop product create (prompted)", create),
    "product-browse": ("source-coop product list -i", browse),
}
