const request = require('request');
const baseUrl = "http://localhost:8080/changepassword";

describe('Change Password API endpoint', function() {
    it("PUT /changepassword should return status 400 for mismatched new passwords", function(done) {
        const data = {
            email: '1234@gmail.com',
            old_password: 'oldPassword123',
            new_password: 'newPassword123',
            repeat_password: 'Password123' //A different password with new password
        };
    
        request.put(
            {url: baseUrl, json: data},
            function(error, response, body) {
                expect(response.statusCode).toBe(400);
                expect(body.message).toBe('New passwords do not match.');
                done();
            }
        );
    });
});