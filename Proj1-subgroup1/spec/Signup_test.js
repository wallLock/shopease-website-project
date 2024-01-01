const request = require('request');
const baseUrl = "http://localhost:8080/register";

describe('API endpoint', function(){
    it("POST /register should return status 200", function(done){
            const data = {
                email: 'test3@example.com',
                password: 'testPassword',
                username: 'testUser3',
                phone_number: '1234567890',
                address: '123 Test St'
            };

            request.post(
                {url: baseUrl,
                json: data},
                function(error, response, body){
                    expect(response.statusCode).toBe(200);
                    done();
                }
            )
    });

    it("Post /register should return status 400 if email is already existed", function(done){
        const data2={
                email: 'user1@example.com',
                password: 'Password123',
                username: 'testUser2',
                phone_number: '1234567890',
                address: '123 Test St'
        };

        request.post(
            {url: baseUrl,
            json: data2},
            function(error, response, body){
                expect(response.statusCode).toBe(400);
                done();
            }
        )
    });
    it("Post /register should return status 400 if username is already existed", function(done){
        const data2={
                email: 'test2@example.com',
                password: 'Password123',
                username: 'user2',
                phone_number: '1234567890',
                address: '123 Test St'
        };

        request.post(
            {url: baseUrl,
            json: data2},
            function(error, response, body){
                expect(response.statusCode).toBe(400);
                done();
            }
        )
    });
})