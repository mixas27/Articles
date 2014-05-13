Многие проекты, использующие для аутентикации пользователей Spring Security, сталкиваются со следующей проблемой: при входе в приложение с использованием «remember me»  пользователей то и дело разлогинивает с выбросом  CookieTheftException. Так, подобная проблема была найдена на багтрекере  [Atlassian|https://jira.atlassian.com/browse/STASH-3054] и [Grails|https://jira.grails.org/browse/GPSPRINGSECURITYCORE-70]. Не обошла стороной эта проблема и наш родной [Javatalks|http://jira.jtalks.org/browse/JC-1743].

Для того чтобы понять почему выбрасывается данное исключение нужно разобраться в методах реализации функционала «remember me».
В Spring security для этого используется два основных подхода:
1.    Подход, основанный на хешировании токенов (Simple hash-based token approach);
2.    Подход, основанный на сохраняемых токенах (Persistent token approach).

Simple hash-based token approach использует md5-хеширование для реализации "remember-me" стратегии. Реализуется всё это в классе org.springframework.security.web. authentication.rememberme. TokenBasedRememberMeServices. При первом успешном входе пользователя с включённой опцией "запомнить меня" срабатывает метод onLoginSuccess, который и устанавливает значение remember-me куки. Сам файл cookie формируется следующим образом:

base64(username + ":" + expirationTime + ":" +md5Hex(username + ":" + expirationTime + ":" password + ":" + key))

    username:          Имя пользователя
    password:          Пароль пользователя
    expirationTime:    Дата и время окончания срока действия cookie (в милисекундах)
    key:               Уникальный ключ приложения

Cрок действия файла cookie устанавливается равным двум неделям. И, пока пока этот файл не устарел и не удалён пользователем, пользователь не будет вынужден при входе на страницу сайта вводить свои учётные данные. При последующем входе срабатывать будет уже метод processAutoLoginCookie, который будет искать пользователя по имени, полученном из cookie. А так же вычислять md5 хэш имени конкатенации имени пользователя, даты устаревания, пароля и ключа и сравнивать его с полученным из cookie. Если всё пройдёт успешно пользователь будет авторизован.

Недостатки:
	1. Недостаточная безопасность (файлы cookies на протяжении всего времени жизни не изменяются, а значит легко могут быть украдены и использованы злоумышленником для входа в приложение)
	2. Необходимость повторного входа после смены пароля, так как файл cookie зависит от пароля

Persistent token approach реализуется в классе org.springframework.security. web.authentication.rememberme.PersistentTokenBasedRememberMeServices и основан на сохранении токенов в хранилище. При данном подходе сам токен представляет собой объект класса PersistentRememberMeToken, в котором хранятся следующие данные :
	1. Значение токена
	2. Серия токена
	3. Имя пользователя
	4. Дата и время окончания срока действия токена
При этом механизм сохранения должен реализовывать интерфейс PersistentTokenRepository.
На данный момент существуют две общеизвестных реализации данного интерфейса: InMemoryTokenRepositoryImpl и JdbcTokenRepositoryImpl.
InMemoryTokenRepositoryImpl - хранилище на основе обычного HashMap. В реальных проектах его рекомендуется использовать исключительно для отладки.
JdbcTokenRepositoryImpl - хранилище основанное на реляционной базе данных.  Как можно заметить по названию данного класса, механизмом доступа к хранилищу является spring jdbc. При использовании данного хранилища в базе данных приложения будет создана таблица persistent_logins со столбцами, соответствующими полям класса PersistentRememberMeToken. Первичным ключом будет являться серия токена.
При первом успешном входе пользователя в приложение с включённой опцией "запомнить меня" сработает метод onLoginSuccess. В данном методе создаётся новый объект класса  PersistentRememberMeToken, в котором значение и серия токена это случайным образом сгенерированные строки закодированные по алгоритму base64. Файл cookie формируется следующим образом:

base64(tokenSeries + ":" + tokenValue)

tokenSeries:         Серия токена
tokenValue:          Значение токена

Лично мной было замечено, что первые 34 символа куки отвечают за серию, последний символ незначащий, а остальные - значение токена.
Данный подход лишён недостатков предыдущего:
	1. При каждом входе пользователя с использованием механизма «remember me» значение токена генерируется случайно и файл cookie переписывается
	2. Значение файла  cookie не зависит от пароля пользователя, а значит при смене пароля повторный вход не требуется
При последующем входе пользователя будет срабатывать уже метод processAutoLoginCookie. Данный метод отыскивает токен в хранилище по его серии и, если таковой был найден и не устарел, проверяет совпадают ли значение токена в файле cookie с сохранённым в хранилище. Затем, если всё прошло успешно, случайно генерируется новое значение токена, которое записывается в хранилище и файл cookie. 
Если же токен по серии не был найден, пользователь входит в приложение как аноним, потому что могут существовать механизмы удаления устаревших токенов из хранилища.
Если значение токена найденного в хранилище не совпадает со значением токена в файле cookie считается, что куки могли быть похищены злоумышленником.  И пользователь уведомляется об этом по средствам выбрасывания CookieTheftException.

Обычно текст ошибки выглядит следующим образом: 

RememberMe exception:
org.springframework.security.web.authentication.rememberme.CookieTheftException: Invalid remember-me token (Series/token) mismatch. Implies previous cookie theft attack.

	
Однако, несовпадение значения токена в хранилище и файлах cookie может вызывать не только похищение последних, но и последовательные запросы от одного клиента, проходящие в достаточно короткий промежуток времени через метод  processAutoLoginCookie. 
Происходит это по следующей схеме:
	- клиент отправляет серверу запрос 1
	- не дождавшись ответа на запрос 1, клиент отправляет запрос 2
	- запрос 1 попадает в метод  processAutoLoginCookie
	- из базы извлекается токен, значение которого совпадает со значением токена в файле cookie запроса 1
	- генерируется новое значение токена, которое сохраняется в базу данных и cookie ответа на запрос 1
	- в это время запрос 2 со старыми куками попадает в метод processAutoLoginCookie
	- из базы извлекается токен, значение которого изменено запросом 1
	- после сравнения значений выбрасывается  CookieTheftException, так как значения не совпадают.

При этом возникает вполне резонный вопрос: «как такое возможно?». 
Самой очевидной причиной является то, что разного рода ресурсы такие как изображениея, файлы скриптов, таблицы стилей проходят через remember me фильтры Spring Security. Исправляется это достаточно просто. Нужно лишь добавить исключения для фильтров в файл secutity-context.xml. Для Spring Security версии ниже 3.1 это будет выглядеть следующим образом:

    <security:intercept-url pattern="/resources/**" filters="none"/>
    <security:intercept-url pattern="/admin/logo" filters="none"/>
    <security:intercept-url pattern="/admin/icon/**" filters="none"/>
    <security:intercept-url pattern="/errors/**" filters="none"/>
    <security:intercept-url pattern="/users/*/avatar" filters="none"/>
    
Начиная со  Spring Security 3.1 использование атрибута filters="none" считается устаревшим, и вместо этого рекомендуют использовать множественные тэги <http>:
 
    <http pattern="/resources/**" security="none"/>
    <http pattern="/admin/logo" security="none"/>
    <http pattern="/admin/icon/**" security="none"/>
    <http pattern="/errors/**" security="none"/>
    <http pattern="/users/*/avatar" security="none"/>

Другим источником множественных запросов является пердзагрузка веб-страниц браузером, в частности Google Chrome. Работает она следующим образом. Когда пользователь начинает вводить что-нибудь в адресную строку, браузер автоматически загружает содержимое страниц, которые считает наиболее релевантными введённому запросу. К тому времени как пользователь отдаёт команду перейти на сайт, часть данных, скорее всего, окажется уже загруженной.  Однако, на практике случается так, что ответ на запрос предзагрузки не успевает дойти до клиента, когда пользователь отдаёт команду перехода на сайт. И запрос со старыми значениями cookie попадает в метод processAutoLoginCookie из-за чего и вызывается CookieTheftException. 
Особо осложняет всё это тот факт, что Google Chrome не посылает никаких отличительных хедеров в запросе на предзагрузку и вообще не позволяет никак отличтить его от обычного запроса.   Выходит, единственной отличительной особенностью предзагрузочного запроса является то, что сразу за ним следует запрос с абсолютно такими же данными в файлах cookie. 
Для того, чтобы отследить это логичным является создание кэша информации о токенах, который будет сохранять серию токена, его значение а так же время помещения в кэш. Так как нету никакой необхожимости сохранять инфомацию о нескольких токенах одного пользователя, наиболее подходящей структурой данных для такого кэша является Map, ключом которой будет серия токена, а значением некий класс CachedRememberMeTokenInfo, листинг которого представлен ниже:

public class CachedRememberMeTokenInfo {

    private String value;
    long cachingTime;

    public CachedRememberMeTokenInfo(String tokenValue, long cachingTime) {
        this.value = tokenValue;
        this.cachingTime = cachingTime;
    }

    /**
     * Gets token date and time of token caching as milliseconds
     * @return Date and time of token caching
     */
    public long getCachingTime() {
        return cachingTime;
    }

    public String getValue() {
        return value;
    }
}

Далее нам необходимо создать класс RememberMeServices, расширяющий стандартный класс PersistentTokenBasedRememberMeServices и переопределить в нём метод processAutoLoginCookie, таким образом чтобы при первом запросе инфомация о токене сохранялась в кэш и вход пользователя выполнялся в штатном режиме. При последующих  же запросах необходимо проверять кэш на наличие текущего токена и, если такой присутствует и был сохранён недавно, выполнять вход пользователя без вызова метода класса предка. Ниже представлена моя реализация данного класса: 

public class RememberMeServices extends PersistentTokenBasedRememberMeServices {
    private final static String REMOVE_TOKEN_QUERY = "DELETE FROM persistent_logins WHERE series = ? AND token = ?";
    // We should store a lot of tokens to prevent cache overflow
    private static final int TOKEN_CACHE_MAX_SIZE = 100;
    private final RememberMeCookieDecoder rememberMeCookieDecoder;
    private final JdbcTemplate jdbcTemplate;
    private final Map<String, CachedRememberMeTokenInfo> tokenCache = new ConcurrentHashMap<>();
    private PersistentTokenRepository tokenRepository = new InMemoryTokenRepositoryImpl();
    // 5 seconds should be enough for processing request and sending response to client
    private int cachedTokenValidityTime = 5 * 1000;

    /**
     * @param rememberMeCookieDecoder needed for extracting rememberme cookies
     * @param jdbcTemplate            needed to execute the sql queries
     * @throws Exception - see why {@link PersistentTokenBasedRememberMeServices} throws it
     */
    public RememberMeServices(RememberMeCookieDecoder rememberMeCookieDecoder, JdbcTemplate jdbcTemplate)
            throws Exception {
        super();
        this.rememberMeCookieDecoder = rememberMeCookieDecoder;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Causes a logout to be completed. The method must complete successfully.
     * Removes client's token which is extracted from the HTTP request.
     * {@inheritDoc}
     */
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String cookie = rememberMeCookieDecoder.exctractRememberMeCookieValue(request);
        if (cookie != null) {
            String[] seriesAndToken = rememberMeCookieDecoder.extractSeriesAndToken(cookie);
            if (logger.isDebugEnabled()) {
                logger.debug("Logout of user " + (authentication == null ? "Unknown" : authentication.getName()));
            }
            cancelCookie(request, response);
            jdbcTemplate.update(REMOVE_TOKEN_QUERY, seriesAndToken);
            tokenCache.remove(seriesAndToken[0]);
            validateTokenCache();
        }
    }

    /**
     * Solution for preventing "remember-me" bug. Some browsers sends preloading requests to server to speed-up
     * page loading. It may cause error when response of preload request not returned to client and second request
     * from client was send. This method implementation stores token in cache for <link>CACHED_TOKEN_VALIDITY_TIME</link>
     * milliseconds and check token presence in cache before process authentication. If there is no equivalent token in
     * cache authentication performs normally. If equivalent present in cache we should not update token in database.
     * This approach can provide acceptable security level and prevent errors.
     * {@inheritDoc}
     * @see <a href="http://jira.jtalks.org/browse/JC-1743">JC-1743</a>
     * @see <a href="https://developers.google.com/chrome/whitepapers/prerender?csw=1">Page preloading in Google Chrome</a>
     */
    @Override
    protected UserDetails processAutoLoginCookie(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
        if (cookieTokens.length != 2) {
            throw new InvalidCookieException("Cookie token did not contain " + 2 +
                    " tokens, but contained '" + Arrays.asList(cookieTokens) + "'");
        }

        final String presentedSeries = cookieTokens[0];
        final String presentedToken = cookieTokens[1];

        PersistentRememberMeToken token = tokenRepository.getTokenForSeries(presentedSeries);

        if (token == null) {
            // No series match, so we can't authenticate using this cookie
            throw new RememberMeAuthenticationException("No persistent token found for series id: " + presentedSeries);
        }

        UserDetails details = null;

        if (isTokenCached(presentedSeries, presentedToken)) {
            tokenCache.remove(presentedSeries);
            details = getUserDetailsService().loadUserByUsername(token.getUsername());
            rewriteCookie(token, request, response);
        } else {
            /* IMPORTANT: We should store token in cache before calling <code>loginWithSpringSecurity</code> method.
               Because execution of this method can take a long time.
             */
            cacheToken(token);
            try {
                details = loginWithSpringSecurity(cookieTokens, request, response);
            //We should remove token from cache if cookie really was stolen or other authentication error occurred
            } catch (CookieTheftException ex) {
                tokenCache.remove(token.getSeries());
                throw ex;
            } catch (RememberMeAuthenticationException ex) {
                tokenCache.remove(token.getSeries());
                throw ex;
            }
        }
        validateTokenCache();

        return details;
    }

    /**
     * Calls PersistentTokenBasedRememberMeServices#processAutoLoginCookie method.
     * Needed for possibility to test.
     */
    @VisibleForTesting
    UserDetails loginWithSpringSecurity(String[] cookieTokens, HttpServletRequest request, HttpServletResponse response) {
        return super.processAutoLoginCookie(cookieTokens, request, response);
    }

    /**
     * Sets valid cookie to response
     * Needed for possibility to test.
     */
    @VisibleForTesting
    void rewriteCookie(PersistentRememberMeToken token, HttpServletRequest request, HttpServletResponse response) {
        setCookie(new String[] {token.getSeries(), token.getTokenValue()}, getTokenValiditySeconds(), request, response);
    }

    @Override
    public void setTokenRepository(PersistentTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
        super.setTokenRepository(tokenRepository);
    }

    /**
     * Stores token in cache.
     * @param token Token to be stored
     * @see CachedRememberMeTokenInfo
     */
    private void cacheToken(PersistentRememberMeToken token) {
        if (tokenCache.size() >= TOKEN_CACHE_MAX_SIZE) {
            validateTokenCache();
        }
        CachedRememberMeTokenInfo tokenWrapper = new CachedRememberMeTokenInfo(token.getTokenValue(), System.currentTimeMillis());
        tokenCache.put(token.getSeries(), tokenWrapper);
    }

    /**
     * Removes from cache tokens which were stored more than <link>CACHED_TOKEN_VALIDITY_TIME</link> milliseconds ago.
     */
    private void validateTokenCache() {
        for (Map.Entry<String, CachedRememberMeTokenInfo> entry: tokenCache.entrySet()) {
            if (!isTokenWrapperValid(entry.getValue())) {
                tokenCache.remove(entry);
            }
        }
    }

    /**
     * Checks if given tokenWrapper valid.
     * @param tokenWrapper Token wrapper to be checked
     * @return <code>true</code> tokenWrapper was stored in cache less than <link>CACHED_TOKEN_VALIDITY_TIME</link> milliseconds ago.
     * <code>false</code> otherwise.
     * @see CachedRememberMeTokenInfo
     */
    private boolean isTokenWrapperValid(CachedRememberMeTokenInfo tokenWrapper) {
        if ((System.currentTimeMillis() - tokenWrapper.getCachingTime()) >= cachedTokenValidityTime) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * Checks if token with given series and value stored in cache
     * @param series series to be checked
     * @param value value to be checked
     * @return <code>true</code> if token stored in cache< <code>false</code> otherwise.
     */
    private boolean isTokenCached(String series, String value) {
        if (tokenCache.containsKey(series) && isTokenWrapperValid(tokenCache.get(series))
                && value.equals(tokenCache.get(series).getValue())) {
            return true;
        }
        return false;
    }

    /**
     * Needed for possibility to test.
     */
    public void setCachedTokenValidityTime(int cachedTokenValidityTime) {
        this.cachedTokenValidityTime = cachedTokenValidityTime;
    }
}
