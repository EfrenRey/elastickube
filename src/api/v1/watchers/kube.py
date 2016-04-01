"""
Copyright 2016 ElasticBox All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import copy
import logging

from tornado.gen import coroutine, Return
from tornado.httpclient import HTTPError

from data.query import Query


class KubeWatcher(object):

    ACTIONS_METADATA = {
        "instances": {
            "required_params": [],
            "init": {
                "resources": {
                    "pods": {
                        "resource": "pods",
                        "type": "PodList",
                        "method": "GET",
                        "parameters": {
                            "namespace": "%(namespace)s"
                        }
                    },
                    "replicationcontrollers": {
                        "resource": "replicationcontrollers",
                        "type": "ReplicationControllerList",
                        "method": "GET",
                        "parameters": {
                            "namespace": "%(namespace)s"
                        }
                    },
                    "services": {
                        "resource": "services",
                        "type": "ServiceList",
                        "method": "GET",
                        "parameters": {
                            "namespace": "%(namespace)s"
                        }
                    }
                }
            },
            "watch": {
                "resources": {
                    "pods": {
                        "resource": "pods",
                        "type": "PodList",
                        "method": "WATCH",
                        "parameters": {
                            "namespace": "%(namespace)s",
                            "resourceVersion": "%(resourceVersionPodList)s"
                        }
                    },
                    "replicationcontrollers": {
                        "resource": "replicationcontrollers",
                        "type": "ReplicationControllerList",
                        "method": "WATCH",
                        "parameters": {
                            "namespace": "%(namespace)s",
                            "resourceVersion": "%(resourceVersionReplicationControllerList)s"
                        }
                    },
                    "services": {
                        "resource": "services",
                        "type": "ServiceList",
                        "method": "WATCH",
                        "parameters": {
                            "namespace": "%(namespace)s",
                            "resourceVersion": "%(resourceVersionServiceList)s"
                        }
                    }
                }
            }
        },
        "instance": {
            "params": ["namespace", "kind", "name"],
            "required_params": ["namespace", "kind", "name"],
            "Pod": {
                "init": {
                    "resources": {
                        "pods": {
                            "resource": "pods",
                            "type": "Pod",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s"
                            }
                        },
                        "metrics": {
                            "resource": "pods",
                            "type": "MetricList",
                            "method": "METRICS",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s"
                            }
                        },
                        "events": {
                            "resource": "events",
                            "type": "EventList",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.namespace=%(namespace)s,"
                                                  "involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                },
                "watch": {
                    "resources": {
                        "pods": {
                            "type": "Pod",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s",
                                "resourceVersion": "%(resourceVersionPod)s"
                            }
                        },
                        "events": {
                            "type": "EventList",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "resourceVersion": "%(resourceVersionEventList)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.namespace=%(namespace)s,"
                                                  "involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                }
            },
            "ReplicationController": {
                "init": {
                    "resources": {
                        "replicationcontrollers": {
                            "resource": "replicationcontrollers",
                            "type": "ReplicationController",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s"
                            }
                        },
                        "events": {
                            "resource": "events",
                            "type": "EventList",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.kind=%(kind)s,"
                                                  "involvedObject.namespace=%(namespace)s,involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                },
                "watch": {
                    "resources": {
                        "replicationcontrollers": {
                            "resource": "replicationcontrollers",
                            "type": "ReplicationController",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s",
                                "resourceVersion": "%(resourceVersionReplicationController)s"
                            }
                        },
                        "events": {
                            "resource": "events",
                            "type": "EventList",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "resourceVersion": "%(resourceVersionEventList)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.kind=%(kind)s,"
                                                  "involvedObject.namespace=%(namespace)s,involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                }
            },
            "Service": {
                "init": {
                    "resources": {
                        "services": {
                            "resource": "services",
                            "type": "Service",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s"
                            }
                        },
                        "endpoints": {
                            "resource": "endpoints",
                            "type": "Endpoints",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s"
                            }
                        },
                        "events": {
                            "resource": "events",
                            "type": "EventList",
                            "method": "GET",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.kind=%(kind)s,"
                                                  "involvedObject.namespace=%(namespace)s,involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                },
                "watch": {
                    "resources": {
                        "services": {
                            "resource": "services",
                            "type": "Service",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s",
                                "resourceVersion": "%(resourceVersionService)s"
                            }
                        },
                        "endpoints": {
                            "resource": "endpoints",
                            "type": "Endpoints",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "name": "%(name)s",
                                "resourceVersion": "%(resourceVersionEndpoints)s"
                            }
                        },
                        "events": {
                            "resource": "events",
                            "type": "EventList",
                            "method": "WATCH",
                            "parameters": {
                                "namespace": "%(namespace)s",
                                "resourceVersion": "%(resourceVersionEventList)s",
                                "fieldSelector": ("involvedObject.name=%(name)s,involvedObject.kind=%(kind)s,"
                                                  "involvedObject.namespace=%(namespace)s,involvedObject.uid=%(uid)s")
                            }
                        }
                    }
                }
            }
        }
    }

    def __init__(self, message, settings, user, callback):
        logging.info("Initializing KubeWatcher")

        self.watchers = dict()
        self.resources_config = dict()
        self.connected = False
        self.params = dict()

        self.settings = settings
        self.callback = callback
        self.message = message
        self.user = user

        self.validate_message()

    @coroutine
    def watch(self):
        def done_callback(future):
            logging.warn("Disconnected from kubeclient.")
            if future.exception():
                logging.exception(future.exception())

            if self.connected and (isinstance(future.exception(), HTTPError) and future.exception().code == 599):
                for watcher_key, watcher_value in self.watchers.iteritems():
                    if watcher_value == future:
                        for name, metadata in self.resources_config.get("watch", {})["resources"].iteritems():
                            if watcher_key != metadata["type"]:
                                continue

                            self.watchers[watcher_key] = getattr(
                                self.settings["kube"][name], metadata["method"].lower())(
                                    on_data=self.data_callback,
                                    **self.get_params(metadata["parameters"]))

                            self.watchers[watcher_key].add_done_callback(done_callback)
                            logging.debug("Reconnected watcher for %s with params %s", watcher_key, self.params)

        logging.info("Starting watch KubeWatcher for action %s with params %s", self.message["action"], self.params)
        yield self.initialize_data()

        self.connected = True
        try:
            logging.debug("Starting watch %s connected", self.message["action"])

            watch_config = self.resources_config.get("watch", {})
            for resource, resource_metadata in watch_config["resources"].iteritems():
                self.watchers[resource_metadata["type"]] = getattr(
                    self.settings["kube"][resource], resource_metadata["method"].lower())(
                        on_data=self.data_callback,
                        **self.get_params(resource_metadata["parameters"]))

                self.watchers[resource_metadata["type"]].add_done_callback(done_callback)
                logging.debug("Added watcher for resource %s and params %s", resource_metadata["type"], self.params)

        except HTTPError as http_error:
            logging.exception(http_error)
            if self.connected:
                self.callback(dict(
                    action=self.message["action"],
                    operation="watched",
                    status_code=400,
                    correlation=self.message["correlation"],
                    body={"error": {"message": "Failed to connect to event source."}},
                ))

    @coroutine
    def data_callback(self, data):
        logging.debug("InstancesWatcher data_callback")

        if "type" not in data:
            logging.warn("Unexpected message from Kubernetes: %s", data)
            raise Return()

        operation = "updated"
        if data["type"] == "ADDED":
            operation = "created"
        elif data["type"] == "DELETED":
            operation = "deleted"
        elif data["type"] == "ERROR":
            logging.warn("Error raised from Kubernetes: %s", data["object"])
            raise Return()

        resource_list = data["object"]["kind"]
        if resource_list not in self.watchers.keys():
            resource_list += "List"

        self.params["resourceVersion" + resource_list] = data["object"]["metadata"]["resourceVersion"]

        response = dict(
            action=self.message["action"],
            operation=operation,
            status_code=200,
            body=data["object"]
        )

        self.callback(response)
        raise Return()

    @coroutine
    def initialize_data(self):
        items = []

        init_config = self.resources_config.get("init", {})
        for resource, resource_metadata in init_config["resources"].iteritems():
            result = yield getattr(
                self.settings["kube"][resource_metadata["resource"]],
                resource_metadata["method"].lower())(**self.get_params(resource_metadata["parameters"]))

            self.params["resourceVersion" + result["kind"]] = result["metadata"]["resourceVersion"]

            documents = []
            if "items" in result:
                for item in result.get("items", []):
                    item["kind"] = result["kind"].replace("List", "")
                    documents.append(item)
            else:
                self.params["uid"] = result["metadata"]["uid"]
                documents.append(result)

            items.extend(documents)

        self.callback(dict(
            action=self.message["action"],
            operation="watched",
            correlation=self.message["correlation"],
            status_code=200,
            body=items
        ))

    def unwatch(self):
        logging.info("Stopping watch %s with params %s", self.message["action"], self.params)
        for watcher in self.watchers.values():
            watcher.cancel()

        self.watchers = dict()
        self.connected = False
        self.params = dict(namespace=None, name=None)

    def validate_message(self):
        for required_param in self.ACTIONS_METADATA[self.message["action"]]["required_params"]:
            if required_param not in self.message["body"]:
                self.callback(dict(
                    action=self.message["action"],
                    operation=self.message["operation"],
                    correlation=self.message["correlation"],
                    body={"message": "Missing %s in request body" % required_param},
                    status_code=400
                ))

                raise RuntimeError()
            else:
                self.params[required_param] = self.message["body"][required_param]

        if "kind" in self.params:
            self.resources_config = copy.deepcopy(
                self.ACTIONS_METADATA[self.message["action"]][self.params["kind"]])
        else:
            self.resources_config = copy.deepcopy(self.ACTIONS_METADATA[self.message["action"]])

    @coroutine
    def check_permissions(self, operation, document):
        logging.debug("check_permissions for user %s and operation %s on kube watch", self.user["username"], operation)
        if self.user["role"] != "administrator":
            if "namespace" not in document:
                raise Return(False)

            namespace = yield Query(self.settings["database"], "Namespaces").find_one({"name": document["namespace"]})
            if "members" in namespace and self.user["username"] not in namespace["members"]:
                raise Return(False)

        raise Return(True)

    def get_params(self, arguments):
        params = dict()
        for key, value in copy.deepcopy(arguments).iteritems():
            try:
                formatted_value = value % self.params
                if formatted_value:
                    params[key] = formatted_value
            except KeyError:
                # Skip missing parameters
                pass

        return params
