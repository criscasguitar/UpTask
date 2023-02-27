<?php

namespace Model;

class Usuario extends ActiveRecord {
    protected static $tabla = 'usuarios';
    protected static $columnasDB = ['id', 'nombre', 'email', 'password', 'token', 'confirmado'];

    public function __construct($args = []) {
        
        $this->id = $args['id'] ?? null;
        $this->nombre = $args['nombre'] ?? '';
        $this->email = $args['email'] ?? '';
        $this->password = $args['password'] ?? '';
        $this->password2 = $args['password2'] ?? '';
        $this->password_actual = $args['password_actual'] ?? '';
        $this->password_nuevo = $args['password_nuevo'] ?? '';
        $this->token = $args['token'] ?? '';
        $this->confirmado = $args['confirmado'] ?? 0;
    }
    // Validar el login de usuarios
    public function validarLogin() {
 /*        if(!$this->nombre) {
            self::$alertas['error'] [] = 'El nombre del Usuario es obligatorio';
        }
         */
        if(!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            self::$alertas['error'][] = 'El Email no es válido';
        }

        if(!$this->email) {
            self::$alertas['error'] [] = 'El Email del Usuario es obligatorio';
        }

        return self::$alertas;
    }

    //validacion para cuentas nuevas
    public function validarNuevaCuenta() {
        if(!$this->nombre) {
            self::$alertas['error'] [] = 'El nombre del Usuario es obligatorio';
        }

        if(!$this->email) {
            self::$alertas['error'] [] = 'El Email del Usuario es obligatorio';
        }

        if(!$this->password) {
            self::$alertas['error'] [] = 'El Password no puede ir vacio';
        }

        if(strlen($this->password) < 6) {
            self::$alertas['error'] [] = 'El Password debe de tener al menos 6 caracteres';
        }
        if($this->password !== $this->password2) {
            self::$alertas['error'] [] = 'Los password son diferentes';   
        }

        return self::$alertas;
    }

    //Valida Email
    public function validarEmail() {
        if(!$this->email) {
            self::$alertas['error'][] = 'El Email es Obligatorio';
        }

        if(!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            self::$alertas['error'][] = 'El Email no es válido';
        }

        return self::$alertas;
    }

    // Validar Perfil
    public function validar_perfil() {
        if(!$this->nombre) {
            self::$alertas['error'][] = 'El Nombre es obligatorio';
        }
        if(!$this->email) {
            self::$alertas['error'][] = 'El Email es obligatorio';
        }
        return self::$alertas;
    }

    //Valida el Password
    public function validarPassword() {
        if(!$this->password) {
            self::$alertas['error'] [] = 'El Password no puede ir vacio';
        }

        if(strlen($this->password) < 6) {
            self::$alertas['error'] [] = 'El Password debe de tener al menos 6 caracteres';
        }
        return self::$alertas;
    }

    public  function nuevo_password() {
        if(!$this->password_actual) {
            self::$alertas['error'][] = 'El Password Actual no puede ir vacio';
        }
        if(!$this->password_nuevo) {
            self::$alertas['error'][] = 'El Password Nuevo no puede ir vacio';
        }
        if(strlen($this->password_nuevo) < 6) {
            self::$alertas['error'][] = 'El Password debe de Contener al menos 6 caracteres';
        }
        return self::$alertas;
    }

    //COmprobar el password
    public function comprobar_password() : bool {
        return password_verify($this->password_actual, $this->password);
    }

    //hashear el password
    public function hashPassword() {
        $this->password = password_hash($this->password, PASSWORD_BCRYPT);
    }

    //geenerar token
    public function crearToken() {
        $this->token = uniqid();
    }
}