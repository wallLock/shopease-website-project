const request = require('request');
const baseUrl = "http://localhost:8080/changepassword";

describe('Change Password API endpoint', function() {
    it("PUT /changepassword should return status 200 for successful password change", function(done) {
        const data = {
            email: '1234@gmail.com',
            old_password: 'newPassword123', 
            new_password: 'oldPassword123',
            repeat_password: 'oldPassword123' //change old_password and new_password if needed after each test
        };

        request.put(
            {url: baseUrl, json: data},
            function(error, response, body) {
                expect(response.statusCode).toBe(200);
                expect(body.message).toBe('Password changed successfully.');
                done();
            }
        );
    });
});
