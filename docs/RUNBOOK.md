# RUNBOOK - Octopus Manager Quick CLI Recovery

## Variables
NAMESPACE=default
REDIS_HOST=redis.default.svc.cluster.local
REDIS_PORT=6379
REDIS_DB=0
WORKER_ID=<worker-id>
MANAGER_DEPLOY=octopus-manager

## Check cooldown key exists
redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB EXISTS "worker_restart:${WORKER_ID}:cooldown"

## Delete cooldown for a worker (unfreeze)
redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB DEL "worker_restart:${WORKER_ID}:cooldown"

## Delete crash history for a worker
redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB DEL "worker_restart:${WORKER_ID}"

## Force scale a worker deployment (bypass manager)
kubectl scale deployment worker-${WORKER_ID} --replicas=1 -n $NAMESPACE

## Stop manager to prevent automated actions (emergency)
kubectl scale deployment ${MANAGER_DEPLOY} --replicas=0 -n $NAMESPACE

## Restart manager after fix
kubectl scale deployment ${MANAGER_DEPLOY} --replicas=1 -n $NAMESPACE

## Clear all cooldown keys (use with extreme caution)
redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB KEYS "worker_restart:*:cooldown" | xargs -r -n1 redis-cli -h $REDIS_HOST -p $REDIS_PORT -n $REDIS_DB DEL

## Force scale all worker-* deployments to 1 (emergency)
for d in $(kubectl get deployments -n $NAMESPACE -o name | grep "^deployment/worker-"); do
  kubectl scale "$d" --replicas=1 -n $NAMESPACE
done
