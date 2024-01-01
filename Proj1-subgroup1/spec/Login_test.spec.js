const request = require('request');
const baseUrl = "http://localhost:8080/login";

describe('API endpoint - /login', function () {
    it('should return status 200 for successful login', function (done) {
        const data = {
            email: 'user1@example.com',
            password: 'Jerry@1748'
        };

        request.post(
            {
                url: baseUrl,
                json: data
            },
            function (error, response, body) {
                expect(response.statusCode).toBe(200);
                expect(body.message).toBe('Login successful');
                done();
            }
        );
    });

    it('should return status 401 for incorrect password', function (done) {
        const data2 = {
            email: 'user1@example.com',
            password: 'IncorrectPassword'
        };

        request.post(
            {
                url: baseUrl,
                json: data2
            },
            function (error, response, body) {
                expect(response.statusCode).toBe(401);
                expect(body.message).toBe('Incorrect password');
                done();
            }
        );
    });

    it('should return status 404 for non-existent user', function (done) {
        const data3 = {
            email: 'nonexistent@example.com',
            password: 'SomePassword'
        };

        request.post(
            {
                url: baseUrl,
                json: data3
            },
            function (error, response, body) {
                expect(response.statusCode).toBe(404);
                expect(body.message).toBe('User not found');
                done();
            }
        );
    });
});
