const request = require('supertest');
const server = require('./server');
const Users = require('../auth/auth-model');
const db = require('../database/dbConfig');

const aUser = {username: "lambda", password: "school"};

describe('Server', function() {
    it('runs the test', function() {
        expect(true).toBe(true)
    })

    describe('API is ready to go', function() {
        it('should return 200 OK', function() {
            // make a GET request to /
            return request(server).get('/').then(res => {
                // check that the status code is 200
                expect(res.status).toBe(200);
            })
        })
    });

    describe('Register a new user', function() {
        beforeEach(async () => {
            await db('users').truncate();
        })

        it('adding a new user', async function() {
            return request(server).post('/api/auth/register').send(aUser)
            .then(res => {
                expect(res.status).toBe(201)
                expect(res.type).toMatch(/json/i)
                expect(res.body.username).toBe(aUser.username)
            })
        });
    })

    describe('Can we login?', function(){

        it('User logged in and got the jokes', function() {
            return request(server).post('/api/auth/login')
            .send(aUser)
            .then(res => {
                return request(server).get('/api/jokes').set({Authorization: res.body.payload})
                    .then(jokes => {
                        expect(jokes.body).toHaveLength(20)
                    })

            })
        })
    })

    describe('How many users?', function() {
        it('Should only be one user', async function() {
            const userList = await db('users');
            expect(userList).toHaveLength(1)
        })
    })
})