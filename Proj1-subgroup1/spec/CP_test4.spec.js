const request = require('request');
const baseUrl = "http://localhost:8080/changepassword";

describe('Change Password API endpoint', function() {
    it("PUT /changepassword should return status 404 for non-existent user email", function(done) {
        const data = {
            email: 'nonexist@gmail.com', // A user email that does not exist in the database
            old_password: 'oldPassword123',
            new_password: 'newPassword123',
            repeat_password: 'newPassword123'
        };
    
        request.put(
            {url: baseUrl, json: data},
            function(error, response, body) {
                expect(response.statusCode).toBe(404);
                expect(body.message).toBe('User not found.');
                done();
            }
        );
    });
});