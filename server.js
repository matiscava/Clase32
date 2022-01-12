const express = require('express');
const cluster = require('cluster');
const { cpus } = require('os');
// const isPrime = require('./isPrime')

const PORT = parseInt(process.argv[2]) || 8080;
const modoCluster = process.argv[3] === 'CLUSTER';

function isPrime(num) {
  if ([2, 3].includes(num)) return true;
  else if ([2, 3].some(n => num % n == 0)) return false;
  else {
      let i = 5, w = 2;
      while ((i ** 2) <= num) {
          if (num % i == 0) return false
          i += w
          w = 6 - w
      }
  }
  return true
}

if ( modoCluster && cluster.isMaster ) 
{
  const numCPUs = cpus().length;

  console.log(`Numero de procesadores: ${numCPUs}`);
  console.log(`PID MASTER: ${process.pid}`);

  for (let i = 0 ; i < numCPUs ; i++) 
  {
    console.log(`Forking process number ${i}...`);
    cluster.fork()
  }

  cluster.on( 'exit' , worker => {
    console.log('Worker' , worker.process.pid , 'died' , new Date().toLocaleString() );
    cluster.fork()
  })
}
else
{
  const app = express();
  
  app.get( '/' , ( req , res ) => {
    const primes = [];
    const max = Number(req.query.max) || 1000 ;
    for ( let i = 1 ; i <= max ; i ++) {
        if (isPrime(i)) primes.push(i)
    }
    res.json(primes)
  } )

  app.listen( PORT , () => {
    console.log(`Servidor express escuchando en el puerto ${PORT}`);
    console.log(`PID WORKER ${process.pid}`);
  })
}

