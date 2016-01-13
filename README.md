# Vault Latch 2fac hack

A hack to add two factor authentication to Latch (at this moment the Vault's API is not ready to add more two factor authentications)

# Quick & dirty demo

Enable user&password authentication

    vault auth-enable userpass

Set Multi factor authentication to Latch

    vault write auth/userpass/mfa_config type=latch

Set Latch application id and the secret

    vault write auth/userpass/latch/access app_id=[Latch App ID] app_secret=[Latch App Secret]

Create the user ged in userpass backend

    vault write auth/userpass/users/ged password=ged policies=root

Run the Latch Mobile App and generate a pairing token. Assign the token to the user.

    vault write auth/userpass/latch/users/ged token=[Generated Token]

Test to authenticate. Turn on / off the switch to test.

    vault auth -method=userpass username=ged password=ged

Delete the user in the latch path to disenroll the user  

    vault delete auth/userpass/latch/users/ged 
