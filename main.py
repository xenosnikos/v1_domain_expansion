from flask import Flask
from flask_restful import Api

from controllers.v1_domain_expansion import V1DomainExpansion

app = Flask(__name__)
api = Api(app)

# version 1 apis
api.add_resource(V1DomainExpansion, "/expansion")

if __name__ == "__main__":
    app.run()
