const request = require('request');
const baseUrl = "http://localhost:8080/changepassword";

describe('Change Password API endpoint', function() {
    it("PUT /changepassword should return status 401 for incorrect old password", function(done) {
        const data = {
            email: '1234@gmail.com',
            old_password: 'Password123', // incorrcet old password(different with test case1)
            new_password: 'newPassword123',
            repeat_password: 'newPassword123'
        };
    
        request.put(
            {url: baseUrl, json: data},
            function(error, response, body) {
                expect(response.statusCode).toBe(401);
                expect(body.message).toBe('Old password is incorrect.');
                done();
            }
        );
    });
});