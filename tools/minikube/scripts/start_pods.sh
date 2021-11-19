#!/bin/sh
kubectl get namespace catalog 2>> /dev/null
if [ $? -ne 0 ]; then
	kubectl create namespace catalog
fi

kubectl get configmap --namespace=catalog dbscripts 2>> /dev/null
if [ $? -ne 0 ]; then
	kubectl create --namespace=catalog configmap dbscripts --from-file=./tools/minikube/templates/scripts
fi

kubectl apply --namespace=catalog -f ./tools/minikube/templates/redis-deployment.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/redis-service.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/pg-data-persistentvolumeclaim.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/postgres-deployment.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/postgres-service.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/keycloak-deployment.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/keycloak-service.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/app-claim0-persistentvolumeclaim.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/app-deployment.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/app-service.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/ingress.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/worker-claim0-persistentvolumeclaim.yaml
kubectl apply --namespace=catalog -f ./tools/minikube/templates/worker-deployment.yaml