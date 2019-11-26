
package com.liferay.portal.ejb;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import javax.mail.internet.InternetAddress;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.dotcms.api.system.user.UserService;
import com.dotcms.business.CloseDBIfOpened;
import com.dotcms.enterprise.AuthPipeProxy;
import com.dotcms.enterprise.PasswordFactoryProxy;
import com.dotcms.enterprise.PasswordFactoryProxy.AuthenticationStatus;
import com.dotcms.enterprise.de.qaware.heimdall.PasswordException;
import com.dotcms.rest.api.v1.authentication.DotInvalidTokenException;
import com.dotcms.rest.api.v1.authentication.ResetPasswordTokenUtil;
import com.dotcms.rest.api.v1.authentication.url.UrlStrategy;
import com.dotcms.util.CollectionsUtils;
import com.dotcms.util.ConversionUtils;
import com.dotcms.util.SecurityUtils;
import com.dotcms.util.SecurityUtils.DelayStrategy;
import com.dotcms.util.UrlStrategyUtil;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.DotInvalidPasswordException;
import com.dotmarketing.cms.login.factories.LoginFactory;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.Config;
import com.dotmarketing.util.EmailUtils;
import com.dotmarketing.util.Logger;
import com.dotmarketing.util.Mailer;
import com.dotmarketing.util.UtilMethods;
import com.dotmarketing.util.WebKeys;
import com.liferay.portal.NoSuchUserException;
import com.liferay.portal.PortalException;
import com.liferay.portal.RequiredUserException;
import com.liferay.portal.SystemException;
import com.liferay.portal.UserActiveException;
import com.liferay.portal.UserEmailAddressException;
import com.liferay.portal.UserIdException;
import com.liferay.portal.UserPasswordException;
import com.liferay.portal.auth.Authenticator;
import com.liferay.portal.auth.PrincipalException;
import com.liferay.portal.auth.PrincipalFinder;
import com.liferay.portal.language.LanguageUtil;
import com.liferay.portal.model.Company;
import com.liferay.portal.model.User;
import com.liferay.portal.pwd.PwdToolkitUtil;
import com.liferay.portal.util.PropsUtil;

import com.liferay.util.Encryptor;
import com.liferay.util.EncryptorException;
import com.liferay.util.GetterUtil;
import com.liferay.util.InstancePool;
import com.liferay.util.KeyValuePair;
import com.liferay.util.StringUtil;
import com.liferay.util.Validator;

/**
 * This manager provides interaction with {@link User} objects in terms of authentication,
 * verification, maintenance, etc.
 *
 * @author Brian Wing Shun Chan
 * @version $Revision: 1.3 $
 *
 */
public class UserManagerImpl extends PrincipalBean implements UserManager {

    private static final Log _log = LogFactory.getLog(UserManagerImpl.class);

    // Business methods

    @Override
    public User addUser(String companyId, boolean autoUserId, String userId, boolean autoPassword, String password1, String password2,
            boolean passwordReset, String firstName, String middleName, String lastName, String nickName, boolean male, Date birthday,
            String emailAddress, Locale locale) throws PortalException, SystemException {

        Company company = CompanyUtil.findByPrimaryKey(companyId);

        if (!company.isStrangers() && !hasAdministrator(companyId)) {
            throw new PrincipalException();
        }

        return UserLocalManagerUtil.addUser(companyId, autoUserId, userId, autoPassword, password1, password2, passwordReset, firstName,
                middleName, lastName, nickName, male, birthday, emailAddress, locale);
    }

    @Override
    public int authenticateByEmailAddress(String companyId, String emailAddress, String password) throws PortalException, SystemException {

        return _authenticate(companyId, emailAddress, password, true);
    }

    @Override
    public int authenticateByUserId(String companyId, String userId, String password) throws PortalException, SystemException {

        return _authenticate(companyId, userId, password, false);
    }

    @Override
    public KeyValuePair decryptUserId(String companyId, String userId, String password) throws PortalException, SystemException {

        Company company = CompanyUtil.findByPrimaryKey(companyId);

        try {
            userId = Encryptor.decrypt(company.getKeyObj(), userId);
        } catch (EncryptorException ee) {
            throw new SystemException(ee);
        }

        String liferayUserId = userId;

        try {
            PrincipalFinder principalFinder = (PrincipalFinder) InstancePool.get(PropsUtil.get(PropsUtil.PRINCIPAL_FINDER));

            liferayUserId = principalFinder.toLiferay(userId);
        } catch (Exception e) {
        }

        User user = UserUtil.findByPrimaryKey(liferayUserId);

        AuthenticationStatus authenticationStatus = PasswordFactoryProxy.AuthenticationStatus.NOT_AUTHENTICATED;
        try {
            authenticationStatus = PasswordFactoryProxy.authPassword(password, user.getPassword());
        } catch (PasswordException e) {
            Logger.error(UserManagerImpl.class, "An error occurred generating the hashed password for userId: " + userId, e);
            throw new SystemException("An error occurred generating the hashed password.");
        }

        if (authenticationStatus.equals(PasswordFactoryProxy.AuthenticationStatus.AUTHENTICATED)) {
            if (user.isPasswordExpired()) {
                user.setPasswordReset(true);

                UserUtil.update(user);
            }

            return new KeyValuePair(userId, password);
        } else {
            throw new PrincipalException();
        }
    }

    @Override
    public void deleteUser(String userId) throws PortalException, SystemException {

        if (!hasAdmin(userId)) {
            throw new PrincipalException();
        }

        if (getUserId().equals(userId)) {
            throw new RequiredUserException();
        }

        UserLocalManagerUtil.deleteUser(userId);
    }

    @CloseDBIfOpened
    @Override
    public String encryptUserId(String userId) throws PortalException, SystemException {

        userId = userId.trim().toLowerCase();

        String liferayUserId = userId;

        try {
            PrincipalFinder principalFinder = (PrincipalFinder) InstancePool.get(PropsUtil.get(PropsUtil.PRINCIPAL_FINDER));

            liferayUserId = principalFinder.toLiferay(userId);
        } catch (Exception e) {
        }

        User user = UserUtil.findByPrimaryKey(liferayUserId);

        Company company = CompanyUtil.findByPrimaryKey(user.getCompanyId());

        try {
            return Encryptor.encrypt(company.getKeyObj(), userId);
        } catch (EncryptorException ee) {
            throw new SystemException(ee);
        }
    }

    @Override
    public List<?> findByAnd_C_FN_MN_LN_EA_M_BD_IM_A(String firstName, String middleName, String lastName, String emailAddress,
            Boolean male, Date age1, Date age2, String im, String street1, String street2, String city, String state, String zip,
            String phone, String fax, String cell) throws PortalException, SystemException {

        return UserFinder.findByAnd_C_FN_MN_LN_EA_M_BD_IM_A(getUser().getCompanyId(), firstName, middleName, lastName, emailAddress, male,
                age1, age2, im, street1, street2, city, state, zip, phone, fax, cell);
    }

    @Override
    public List<?> findByC_SMS() throws PortalException, SystemException {
        return UserFinder.findByC_SMS(getUser().getCompanyId());
    }

    @Override
    public List<?> findByOr_C_FN_MN_LN_EA_M_BD_IM_A(String firstName, String middleName, String lastName, String emailAddress, Boolean male,
            Date age1, Date age2, String im, String street1, String street2, String city, String state, String zip, String phone,
            String fax, String cell) throws PortalException, SystemException {

        return UserFinder.findByOr_C_FN_MN_LN_EA_M_BD_IM_A(getUser().getCompanyId(), firstName, middleName, lastName, emailAddress, male,
                age1, age2, im, street1, street2, city, state, zip, phone, fax, cell);
    }

    @Override
    public String getCompanyId(String userId) throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(userId);

        return user.getCompanyId();
    }

    @Override
    public User getDefaultUser(String companyId) throws PortalException, SystemException {

        return UserLocalManagerUtil.getDefaultUser(companyId);
    }

    @Override
    public User getUserByEmailAddress(String emailAddress) throws PortalException, SystemException {

        emailAddress = emailAddress.trim().toLowerCase();

        User user = UserUtil.findByC_EA(getUser().getCompanyId(), emailAddress);

        if (getUserId().equals(user.getUserId()) || hasAdministrator(user.getCompanyId())) {

            return user;
        } else {
            return (User) user.getProtected();
        }
    }

    @Override
    public User getUserById(String userId) throws PortalException, SystemException {

        userId = userId.trim().toLowerCase();

        User user = UserUtil.findByPrimaryKey(userId);

        if (getUserId().equals(userId) || hasAdministrator(user.getCompanyId())) {

            return user;
        } else {
            return (User) user.getProtected();
        }
    }

    @Override
    public User getUserById(String companyId, String userId) throws PortalException, SystemException {

        userId = userId.trim().toLowerCase();

        User user = UserUtil.findByC_U(companyId, userId);

        if (getUserId().equals(userId) || hasAdministrator(user.getCompanyId())) {

            return user;
        } else {
            return (User) user.getProtected();
        }
    }

    @Override
    public String getUserId(String companyId, String emailAddress) throws PortalException, SystemException {

        emailAddress = emailAddress.trim().toLowerCase();

        User user = UserUtil.findByC_EA(companyId, emailAddress);

        return user.getUserId();
    }

    @Override
    public int notifyNewUsers() throws PortalException, SystemException {


        return 0;
    }

    @Override
    public void sendPassword(String companyId, String emailAddress, Locale locale, boolean fromAngular)
            throws PortalException, SystemException {

        emailAddress = emailAddress.trim().toLowerCase();

        if (!Validator.isEmailAddress(emailAddress)) {
            throw new UserEmailAddressException();
        }

        User user = UserUtil.findByC_EA(companyId, emailAddress);

        // we use the ICQ field to store the token:timestamp of the
        // password reset request we put in the email
        // the timestamp is used to set an expiration on the token
        String token = ResetPasswordTokenUtil.createToken();
        user.setIcqId(token + ":" + new Date().getTime());

        UserUtil.update(user);

        // Send new password

        Company company = CompanyUtil.findByPrimaryKey(companyId);

        String url = UrlStrategyUtil.getURL(company, CollectionsUtils.map(UrlStrategy.USER, user, UrlStrategy.TOKEN, token, UrlStrategy.LOCALE, locale),
                (fromAngular) ? UserService.ANGULAR_RESET_PASSWORD_URL_STRATEGY : UserService.DEFAULT_RESET_PASSWORD_URL_STRATEGY);

        String body = LanguageUtil.format(locale, "reset-password-email-body", url, false);
        String subject = LanguageUtil.get(locale, "reset-password-email-subject");

        try {
            EmailUtils.sendMail(user, company, subject, body);
        } catch (Exception ioe) {
            throw new SystemException(ioe);
        }
    }

    @Override
    public void test() {
        String userId = null;

        try {
            userId = getUserId();
        } catch (Exception e) {
            Logger.error(this, e.getMessage(), e);
        }

        _log.info(userId);
    }

    @Override
    public User updateActive(String userId, boolean active) throws PortalException, SystemException {

        userId = userId.trim().toLowerCase();

        User user = UserUtil.findByPrimaryKey(userId);

        if (!hasAdministrator(user.getCompanyId())) {
            throw new PrincipalException();
        }

        if (active == false && getUserId().equals(userId)) {
            throw new RequiredUserException();
        }

        user.setActive(active);

        UserUtil.update(user);

        return user;
    }

    @Override
    public User updateAgreedToTermsOfUse(boolean agreedToTermsOfUse) throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(getUserId());

        user.setAgreedToTermsOfUse(agreedToTermsOfUse);

        UserUtil.update(user);

        return user;
    }

    @Override
    public User updateLastLogin(String loginIP) throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(getUserId());

        if (user.getLoginDate() == null && user.getLastLoginDate() == null) {
        }

        user.setLastLoginDate(user.getLoginDate());
        user.setLastLoginIP(user.getLoginIP());
        user.setLoginDate(new Date());
        user.setLoginIP(loginIP);
        user.setFailedLoginAttempts(0);

        UserUtil.update(user);

        return user;
    }

    @Override
    public void updatePortrait(String userId, byte[] bytes) throws PortalException, SystemException {

    }

    @Override
    public User updateUser(String userId, String password1, String password2, boolean passwordReset)
            throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(userId);

        if (!getUserId().equals(userId) && !hasAdministrator(user.getCompanyId())) {

            throw new PrincipalException();
        }

        return UserLocalManagerUtil.updateUser(userId, password1, password2, passwordReset);
    }

    @Override
    public User updateUser(String userId, String password, String firstName, String middleName, String lastName, String nickName,
            boolean male, Date birthday, String emailAddress, String smsId, String aimId, String icqId, String msnId, String ymId,
            String favoriteActivity, String favoriteBibleVerse, String favoriteFood, String favoriteMovie, String favoriteMusic,
            String languageId, String timeZoneId, String skinId, boolean dottedSkins, boolean roundedSkins, String greeting,
            String resolution, String refreshRate, String comments) throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(userId);

        if (!getUserId().equals(userId) && !hasAdministrator(user.getCompanyId())) {

            throw new PrincipalException();
        }

        return UserLocalManagerUtil.updateUser(userId, password, firstName, middleName, lastName, nickName, male, birthday, emailAddress,
                smsId, aimId, icqId, msnId, ymId, favoriteActivity, favoriteBibleVerse, favoriteFood, favoriteMovie, favoriteMusic,
                languageId, timeZoneId, skinId, dottedSkins, roundedSkins, greeting, resolution, refreshRate, comments);
    }

    // Permission methods

    @Override
    public boolean hasAdmin(String userId) throws PortalException, SystemException {

        User user = UserUtil.findByPrimaryKey(userId);

        if (hasAdministrator(user.getCompanyId())) {
            return true;
        } else {
            return false;
        }
    }

    // Private methods

    /**
     * Authenticates the user based on their e-mail or user ID.
     * 
     * @param companyId - The ID of the company that the user belongs to.
     * @param login - The identification mechanism: The user e-mail, or the user ID.
     * @param password - The user password.
     * @param byEmailAddress - If the user authentication is performed against e-mail, set this to
     *        {@code true}. If it's against the user ID, set to {@code false}.
     * @return A status code indicating the result of the operation: {@link Authenticator#SUCCESS},
     *         {@link Authenticator#FAILURE}, or {@link Authenticator#DNE}.
     * @throws PortalException - There's a problem with the information provided by or retrieved for the
     *         user.
     * @throws SystemException - User information could not be updated.
     */
    private int _authenticate(String companyId, String login, String password, boolean byEmailAddress)
            throws PortalException, SystemException {

        login = login.trim().toLowerCase();

        Logger.debug(this, "Doing authentication for: " + login);

        if (byEmailAddress) {
            if (!Validator.isEmailAddress(login)) {

                Logger.error(this, "Invalid email throwing a UserEmailAddressException: " + login);
                throw new UserEmailAddressException();
            }
        } else {
            if (Validator.isNull(login)) {

                Logger.error(this, "User can not be null, throwing UserIdException: " + login);
                throw new UserIdException();
            }
        }

        if (Validator.isNull(password)) {

            Logger.error(this, "Password can not be null, throwing UserPasswordException");
            throw new UserPasswordException(UserPasswordException.PASSWORD_INVALID);
        }

        int authResult = Authenticator.FAILURE;

        if (byEmailAddress) {

            Logger.debug(this, "Doing PRE authentication by email address for: " + login);

            authResult =
                    AuthPipeProxy.authenticateByEmailAddress(PropsUtil.getArray(PropsUtil.AUTH_PIPELINE_PRE), companyId, login, password);
        } else {

            Logger.debug(this, "Doing PRE authentication by userId for: " + login);

            authResult = AuthPipeProxy.authenticateByUserId(PropsUtil.getArray(PropsUtil.AUTH_PIPELINE_PRE), companyId, login, password);
        }

        User user = null;

        try {
            if (byEmailAddress) {
                user = UserUtil.findByC_EA(companyId, login);
            } else {
                user = UserUtil.findByC_U(companyId, login);
            }
        } catch (NoSuchUserException nsue) {

            Logger.error(this, "Could not find the user: " + nsue.getMessage() + ", return DNE");

            return Authenticator.DNE;
        }

        if (user.isPasswordExpired()) {

            Logger.debug(this, "The Password expired for: " + login);

            user.setPasswordReset(true);

            UserUtil.update(user);
        }

        if (authResult == Authenticator.SUCCESS) {
            if (LoginFactory.passwordMatch(password, user)) {

                Logger.debug(this, "The Password match for: " + login);
                authResult = Authenticator.SUCCESS;
            } else {

                Logger.debug(this, "The Password does not match for: " + login);
                authResult = Authenticator.FAILURE;
            }
        }

        if (authResult == Authenticator.SUCCESS) {
            if (!user.getActive()) {

                Logger.error(this, "Login was success but user is not active, throwing UserActiveException");
                throw new UserActiveException();
            }

            if (byEmailAddress) {

                Logger.debug(this, "Doing POST authentication by email address for: " + login);

                authResult = AuthPipeProxy.authenticateByEmailAddress(PropsUtil.getArray(PropsUtil.AUTH_PIPELINE_POST), companyId, login,
                        password);
            } else {

                Logger.debug(this, "Doing POST authentication by userId for: " + login);

                authResult =
                        AuthPipeProxy.authenticateByUserId(PropsUtil.getArray(PropsUtil.AUTH_PIPELINE_POST), companyId, login, password);
            }
            if (authResult == Authenticator.SUCCESS) {
                // User authenticated, reset failed attempts
                Logger.debug(this, "Setting the user: " + user.getUserId() + ", failed login attempts: 0");
                user.setFailedLoginAttempts(0);
                UserUtil.update(user);
            }
        }

        if (authResult == Authenticator.FAILURE) {

            Logger.debug(this, "Authenticated failed for: " + login);

            try {
                if (byEmailAddress) {
                    AuthPipeProxy.onFailureByEmailAddress(PropsUtil.getArray(PropsUtil.AUTH_FAILURE), companyId, login);
                } else {
                    AuthPipeProxy.onFailureByUserId(PropsUtil.getArray(PropsUtil.AUTH_FAILURE), companyId, login);
                }

                int failedLoginAttempts = user.getFailedLoginAttempts();
                Logger.debug(this, "Current failed login attempts for: " + login + ", is: " + failedLoginAttempts);

                if (Config.getBooleanProperty(WebKeys.AUTH_FAILED_ATTEMPTS_DELAY_STRATEGY_ENABLED, true)) {

                    Logger.debug(this, "Making a delay request for failed login attempts for: " + login + ", with: " + failedLoginAttempts);
                    delayRequest(failedLoginAttempts);
                }

                user.setFailedLoginAttempts(++failedLoginAttempts);
                Logger.debug(this, "Increasing failed login attempts for: " + login + ", with: " + user.getFailedLoginAttempts());

                UserUtil.update(user);

                int maxFailures = GetterUtil.get(PropsUtil.get(PropsUtil.AUTH_MAX_FAILURES_LIMIT), 0);

                Logger.debug(this, "Max failures: " + maxFailures);

                if ((failedLoginAttempts >= maxFailures) && (maxFailures != 0)) {

                    if (byEmailAddress) {

                        Logger.debug(this, "Reporting Max failures by email, maxFailures: " + maxFailures + ", failed login attemps: "
                                + failedLoginAttempts);

                        AuthPipeProxy.onMaxFailuresByEmailAddress(PropsUtil.getArray(PropsUtil.AUTH_MAX_FAILURES), companyId, login);
                    } else {

                        Logger.debug(this, "Reporting Max failures by userId, maxFailures: " + maxFailures + ", failed login attemps: "
                                + failedLoginAttempts);

                        AuthPipeProxy.onMaxFailuresByUserId(PropsUtil.getArray(PropsUtil.AUTH_MAX_FAILURES), companyId, login);
                    }
                }
            } catch (Exception e) {
                Logger.error(this, e.getMessage(), e);
            }
        }

        return authResult;
    }

    /**
     * If the user trying to authenticate has failed to do so, their login process will be penalized in
     * order to prevent potential hacking attacks. The time that the user will have to wait is based on
     * a specific delay strategy. It defaults to raising the {@code defaultSeed} value to the power of
     * 2.
     * 
     * @param defaultSeed - The default time seed in case the delay strategy does not specify one.
     */
    private void delayRequest(int defaultSeed) {
        int seed = defaultSeed;
        String delayStrat = Config.getStringProperty(WebKeys.AUTH_FAILED_ATTEMPTS_DELAY_STRATEGY, "pow");
        String[] stratParams = delayStrat.split(":");
        DelayStrategy strategy;
        try {
            strategy = (UtilMethods.isSet(stratParams[0])) ? DelayStrategy.valueOf(stratParams[0].toUpperCase()) : DelayStrategy.POW;
            if (stratParams.length > 1) {
                seed = ConversionUtils.toInt(stratParams[1], defaultSeed);
            }

            Logger.debug(this, "Doing a delay request, with seed: " + seed + ", defaultSeed: " + defaultSeed + ", strategy: " + strategy);
        } catch (Exception e) {
            Logger.error(this, "The specified delay strategy is invalid. Defaults to POW strategy.", e);
            strategy = DelayStrategy.POW;
        }

        SecurityUtils.delayRequest(seed, strategy);
    }

    /**
     * 
     */
    public void resetPassword(String userId, String token, String newPassword) throws com.dotmarketing.business.NoSuchUserException,
            DotSecurityException, DotInvalidTokenException, DotInvalidPasswordException {
        try {
            if (UtilMethods.isSet(userId) && UtilMethods.isSet(token)) {
                User user = APILocator.getUserAPI().loadUserById(userId);

                if (user == null) {
                    throw new com.dotmarketing.business.NoSuchUserException("");
                }

                ResetPasswordTokenUtil.checkToken(user, token);
                APILocator.getUserAPI().updatePassword(user, newPassword, APILocator.getUserAPI().getSystemUser(), false);
            }
        } catch (DotDataException e) {
            throw new IllegalArgumentException();
        }
    }

}
