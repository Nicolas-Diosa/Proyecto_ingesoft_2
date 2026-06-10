# Proyecto_ingesoft_2
## Participantes en el desarrollo del proyecto
- Nicolás Alejandro Diosa Benavides
- Juan Felipe Fajardo Garzón
- Esteban Prieto Lugo

En este repositorio reside el proyecto final de la asignatura de Ingeniería de Software II, siendo esta una auditoría al ERP Odoo sobre cibherseguridad tratando de responder los siguientes requerimientos:

REQUERIMIENTOS FUNCIONALES
1. Como Administrador de Sistemas, quiero que el acceso se haga mediante MFA para reducir el riesgo de robo de cuentas por ataques de fuerza bruta. 
2. Como Administrativo, quiero tener un registro detallado (logs) de quién modificó registros críticos para garantizar la trazabilidad. 
3. Como Responsable de Cumplimiento, quiero que los datos personales de los clientes estén cifrados en la base de datos para cumplir con las normativas legales de protección de datos. 

REQUERIMIENTOS NO FUNCIONALES
1. El Sistema deberá deshabilitar por completo el Database Manager expuesto en la URL /web/database/manager para evitar que atacantes externos intenten borrar o descargar copias de seguridad. 
2. El Sistema deberá ejecutar escaneos automáticos de vulnerabilidades en los módulos de terceros instalados para mitigar riesgos de código malicioso o puertas traseras (backdoors).
3. El Sistema deberá estar configurado bajo el Principio de Menor Privilegio, de modo que el usuario de la base de datos no tenga permisos de superusuario, para limitar el daño en caso de una inyección SQL. 
4. El Sistema deberá realizar cifrados hacia un almacenamiento (base de datos) para garantizar la continuidad del negocio ante un ataque Man in the Middle.

El informe de auditoría contiene la documentación final de las respuestas y determinación o hallazgos que hizo nuestro grupo, mientras que en el mapeo de Odoo se examina la estructura del sistema.
