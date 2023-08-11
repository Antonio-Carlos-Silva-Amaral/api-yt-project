"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserRepository = void 0;
const mysql_1 = require("../../../mysql");
const uuid_1 = require("uuid");
const bcrypt_1 = require("bcrypt");
const jsonwebtoken_1 = require("jsonwebtoken");
class UserRepository {
    create(request, response) {
        const { name, email, password } = request.body;
        mysql_1.pool.getConnection((err, connection) => {
            if (err) {
                return response.status(500).json(err);
            }
            // Verificar se o e-mail já está cadastrado
            connection.query('SELECT * FROM user WHERE email = ?', [email], (error, result) => {
                if (error) {
                    connection.release();
                    return response.status(500).json(error);
                }
                // Se encontrou um registro com o mesmo e-mail, retornar erro
                if (result.length > 0) {
                    connection.release();
                    return response.status(409).json({ error: 'E-mail já cadastrado' });
                }
                // Caso o e-mail não esteja cadastrado, prosseguir com a criação do usuário
                (0, bcrypt_1.hash)(password, 10, (err, hash) => {
                    if (err) {
                        connection.release();
                        return response.status(500).json(err);
                    }
                    connection.query('INSERT INTO user (user_id, name, email, password) VALUES (?, ?, ?, ?)', [(0, uuid_1.v4)(), name, email, hash], (error, result) => {
                        connection.release();
                        if (error) {
                            return response.status(400).json(error);
                        }
                        response.status(200).json({ message: 'Usuário criado com sucesso' });
                    });
                });
            });
        });
    }
    login(request, response) {
        const { email, password } = request.body;
        mysql_1.pool.getConnection((err, connection) => {
            connection.query('SELECT * FROM user WHERE email = ?', [email], (error, results, fileds) => {
                connection.release();
                if (error) {
                    return response.status(400).json({ error: 'Erro na sua autenticação' });
                }
                (0, bcrypt_1.compare)(password, results[0].password, (err, result) => {
                    if (err) {
                        return response.status(400).json({ error: 'Erro na sua autenticação' });
                    }
                    if (results) {
                        const token = (0, jsonwebtoken_1.sign)({
                            id: results[0].user_id,
                            email: results[0].email
                        }, process.env.SECRET, { expiresIn: '1d' });
                        return response.status(200).json({ token: token, message: 'Token recebido com sucesso ' });
                    }
                });
            });
        });
    }
    getUser(request, response) {
        const decode = (0, jsonwebtoken_1.verify)(request.headers.authorization, process.env.SECRET);
        if (decode.email) {
            mysql_1.pool.getConnection((error, conn) => {
                conn.query('SELECT * FROM user WHERE email=?', [decode.email], (error, resultado, fields) => {
                    conn.release();
                    if (error) {
                        return response.status(400).send({
                            error: error,
                            response: null
                        });
                    }
                    return response.status(201).send({
                        user: {
                            nome: resultado[0].name,
                            email: resultado[0].email,
                            id: resultado[0].user_id,
                        }
                    });
                });
            });
        }
    }
}
exports.UserRepository = UserRepository;
