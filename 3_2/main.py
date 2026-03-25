from typing import Optional

from fastapi import FastAPI, HTTPException, Query

app = FastAPI()

sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99,
}

sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99,
}

sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99,
}

sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99,
}

sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99,
}

sample_products = [
    sample_product_1,
    sample_product_2,
    sample_product_3,
    sample_product_4,
    sample_product_5,
]


@app.get("/products/search")
async def search_products(
    keyword: str = Query(...),
    category: Optional[str] = None,
    limit: int = Query(10, gt=0),
):
    results = []
    for product in sample_products:
        if keyword.lower() in product["name"].lower():
            if category and product["category"].lower() != category.lower():
                continue
            results.append(product)
    return results[:limit]


@app.get("/product/{product_id}")
async def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    return {"error": "Product not found"}

