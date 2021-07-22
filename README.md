# Scan_red
Script para escanear un red dentro de un entorno Linux
Scan_red
Script para escanear un red dentro de un entorno Linux

Permite descubrir las IP de la red en la que se encuentre tu máquina, en una determinada interfaz, indicada por el usuario a la hora de ejecutar el programa. La ejecución se debe realizar en un entorno Linux. Una vez haya encontrado las IP, muestra los puertos que tiene abiertos, tanto para TCP como para UDP, y junto al puerto, se indica el banner del servicio, utilizando la técnica de Banner Grabbing. Además, el resultado se codifica en formato JSON y envia mediante una petición POST a la url: http://127.0.0.1/example/fake_url.php Ten en cuenta que es una URL falsa, y que no responderá a la petición.
