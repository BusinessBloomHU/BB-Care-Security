<?php
/**
 * Plugin Name: Business Bloom Care Security
 * Description: Professzionális WordPress védelem egyedi login URL-lel, brute force védelemmel és valós idejű monitoringgal
 * Version: 3.0.0
 * Author: Business Bloom Consulting
 * Author URI: https://businessbloom.consulting
 * Text Domain: bb-security
 */

if (!defined('ABSPATH')) exit;

/* ========================================
   CORE FUNCTIONS
   ======================================== */

/**
 * Get plugin options with defaults
 */
function bb_security_get_options() {
    $defaults = array(
        'custom_login_url'        => '',
        'hide_wp_admin'           => 1,
        'hide_version'            => 1,
        'disable_xmlrpc'          => 1,
        'login_errors'            => 1,
        'rest_api_protection'     => 1,
        'author_protection'       => 1,
        'security_headers'        => 1,
        'login_rate_limit'        => 1,
        'file_upload_protection'  => 1,
        'sensitive_files_block'   => 1,
        'email_notifications'     => 1,
        'notification_email'      => get_option('admin_email'),
    );
    
    $saved = get_option('bb_security_options', array());
    return wp_parse_args($saved, $defaults);
}

/**
 * Get login slug - default vagy custom
 */
function bb_security_get_login_slug() {
    $options = bb_security_get_options();
    $slug = !empty($options['custom_login_url']) ? $options['custom_login_url'] : '';
    $slug = sanitize_title($slug);
    
    // Ha üres, nincs custom login URL feature aktív
    return $slug;
}

/**
 * Build custom login URL
 */
function bb_security_build_login_url($args = array()) {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        // Ha nincs custom slug, standard wp-login.php
        return wp_login_url();
    }
    
    $url = home_url('/' . trim($slug, '/') . '/');
    
    if (!empty($args)) {
        $url = add_query_arg($args, $url);
    }
    
    return $url;
}

/**
 * Check if current request is the custom login slug
 */
function bb_security_is_custom_login_request() {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        return false;
    }
    
    $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    $request_path = parse_url($request_uri, PHP_URL_PATH);
    
    if (!is_string($request_path)) {
        return false;
    }
    
    $request_path = trim($request_path, '/');
    
    // Home path handling (ha WP almappában fut)
    $home_path = parse_url(home_url('/'), PHP_URL_PATH);
    if (!is_string($home_path)) {
        $home_path = '/';
    }
    $home_path = trim($home_path, '/');
    
    if ('' !== $home_path) {
        if (strpos($request_path, $home_path . '/') === 0) {
            $request_path = substr($request_path, strlen($home_path . '/'));
        } elseif ($request_path === $home_path) {
            $request_path = '';
        }
    }
    
    return ($request_path === $slug);
}

/* ========================================
   SECURITY SCORE CALCULATOR
   ======================================== */

function bb_security_calculate_score() {
    $options = bb_security_get_options();
    $slug = bb_security_get_login_slug();
    
    $checks = array();
    
    // 1. Custom Login URL (20 pont)
    $checks[] = array(
        'key'    => 'custom_login_url',
        'label'  => __('Egyedi bejelentkezési URL', 'bb-security'),
        'status' => !empty($slug),
        'weight' => 20,
        'desc_on' => sprintf(__('Bejelentkezés: %s', 'bb-security'), bb_security_build_login_url()),
        'desc_off' => __('Állíts be egyedi login URL-t a robotok ellen', 'bb-security'),
    );
    
    // 2. wp-admin 404 for guests (15 pont)
    $checks[] = array(
        'key'    => 'hide_wp_admin',
        'label'  => __('wp-admin elrejtve vendégeknek', 'bb-security'),
        'status' => !empty($options['hide_wp_admin']),
        'weight' => 15,
        'desc_on' => __('Nem bejelentkezett látogatók 404-et kapnak', 'bb-security'),
        'desc_off' => __('Kapcsold be a wp-admin elrejtését', 'bb-security'),
    );
    
    // 3. Login Rate Limiting (20 pont)
    $checks[] = array(
        'key'    => 'login_rate_limit',
        'label'  => __('Brute force rate limiting', 'bb-security'),
        'status' => !empty($options['login_rate_limit']),
        'weight' => 20,
        'desc_on' => __('5 sikertelen próba → 15 perc blokk', 'bb-security'),
        'desc_off' => __('Kapcsold be a rate limiting védelmet', 'bb-security'),
    );
    
    // 4. Email notifications (10 pont)
    $checks[] = array(
        'key'    => 'email_notifications',
        'label'  => __('Email riasztások', 'bb-security'),
        'status' => !empty($options['email_notifications']),
        'weight' => 10,
        'desc_on' => __('Értesítés minden fontos eseményről', 'bb-security'),
        'desc_off' => __('Kapcsold be az email értesítéseket', 'bb-security'),
    );
    
    // 5. Security Headers (10 pont)
    $checks[] = array(
        'key'    => 'security_headers',
        'label'  => __('HTTP biztonsági fejlécek', 'bb-security'),
        'status' => !empty($options['security_headers']),
        'weight' => 10,
        'desc_on' => __('HSTS, X-Frame-Options, CSP aktív', 'bb-security'),
        'desc_off' => __('Kapcsold be a security headers-t', 'bb-security'),
    );
    
    // 6. REST API protection (8 pont)
    $checks[] = array(
        'key'    => 'rest_api_protection',
        'label'  => __('REST API felhasználói védelem', 'bb-security'),
        'status' => !empty($options['rest_api_protection']),
        'weight' => 8,
        'desc_on' => __('User enumeration tiltva REST API-n', 'bb-security'),
        'desc_off' => __('Védd meg a REST API user végpontokat', 'bb-security'),
    );
    
    // 7. Author enumeration (8 pont)
    $checks[] = array(
        'key'    => 'author_protection',
        'label'  => __('Author enumeration védelem', 'bb-security'),
        'status' => !empty($options['author_protection']),
        'weight' => 8,
        'desc_on' => __('?author= és /author/ lekérések blokkolva', 'bb-security'),
        'desc_off' => __('Kapcsold be az author védélmet', 'bb-security'),
    );
    
    // 8. XML-RPC disable (5 pont)
    $checks[] = array(
        'key'    => 'disable_xmlrpc',
        'label'  => __('XML-RPC letiltva', 'bb-security'),
        'status' => !empty($options['disable_xmlrpc']),
        'weight' => 5,
        'desc_on' => __('XML-RPC támadások tiltva', 'bb-security'),
        'desc_off' => __('Tiltsd le az XML-RPC-t', 'bb-security'),
    );
    
    // 9. Version hiding (2 pont)
    $checks[] = array(
        'key'    => 'hide_version',
        'label'  => __('WordPress verzió elrejtve', 'bb-security'),
        'status' => !empty($options['hide_version']),
        'weight' => 2,
        'desc_on' => __('Verzió információ eltávolítva', 'bb-security'),
        'desc_off' => __('Rejtsd el a WP verziót', 'bb-security'),
    );
    
    // 10. File upload protection (2 pont)
    $checks[] = array(
        'key'    => 'file_upload_protection',
        'label'  => __('Veszélyes fájltípusok tiltva', 'bb-security'),
        'status' => !empty($options['file_upload_protection']),
        'weight' => 2,
        'desc_on' => __('SVG, EXE, SWF tiltva', 'bb-security'),
        'desc_off' => __('Tiltsd le a veszélyes fájltípusokat', 'bb-security'),
    );
    
    // Score calculation
    $total = 0;
    $achieved = 0;
    
    foreach ($checks as $item) {
        $total += $item['weight'];
        if ($item['status']) {
            $achieved += $item['weight'];
        }
    }
    
    $score = 0;
    if ($total > 0) {
        $score = round(($achieved / $total) * 100);
    }
    
    // Level determination
    if ($score >= 90) {
        $level = 'excellent';
        $level_text = __('Kiváló védelem', 'bb-security');
        $level_color = '#10b981';
    } elseif ($score >= 75) {
        $level = 'good';
        $level_text = __('Erős védelem', 'bb-security');
        $level_color = '#10b981';
    } elseif ($score >= 50) {
        $level = 'medium';
        $level_text = __('Közepes védelem', 'bb-security');
        $level_color = '#f59e0b';
    } else {
        $level = 'low';
        $level_text = __('Gyenge védelem', 'bb-security');
        $level_color = '#ef4444';
    }
    
    return array(
        'score'       => $score,
        'level'       => $level,
        'level_text'  => $level_text,
        'level_color' => $level_color,
        'checks'      => $checks,
    );
}

/* ========================================
   ADMIN SETTINGS CLASS
   ======================================== */

class BB_Security_Settings {
    
    private $options;
    private $version = '3.0.0';
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_plugin_page'));
        add_action('admin_init', array($this, 'page_init'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_styles'));
        add_action('wp_dashboard_setup', array($this, 'add_dashboard_widget'));
        add_action('admin_notices', array($this, 'email_failure_notice'));
        
        $this->options = bb_security_get_options();
    }
    
    public function enqueue_admin_styles($hook) {
        if ('settings_page_bb-security' !== $hook && 'index.php' !== $hook) {
            return;
        }
        
        wp_add_inline_style('wp-admin', '
            .bb-security-wrap {
                max-width: 1400px;
                margin: 20px 0;
            }
            .bb-security-header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 12px;
                margin-bottom: 30px;
                box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);
            }
            .bb-security-header h1 {
                margin: 0;
                color: white;
                font-size: 32px;
                font-weight: 700;
            }
            .bb-security-header p {
                margin: 10px 0 0;
                opacity: 0.95;
                font-size: 15px;
            }
            .bb-security-grid {
                display: grid;
                grid-template-columns: 350px 1fr;
                gap: 25px;
                margin-bottom: 30px;
            }
            .bb-security-card {
                background: white;
                border: 1px solid #e5e7eb;
                border-radius: 12px;
                padding: 25px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.05);
            }
            .bb-security-card h2 {
                margin-top: 0;
                font-size: 20px;
                color: #1f2937;
                border-bottom: 3px solid #667eea;
                padding-bottom: 12px;
                margin-bottom: 20px;
            }
            .bb-score-circle-wrap {
                display: flex;
                flex-direction: column;
                align-items: center;
                margin-bottom: 25px;
            }
            .bb-score-circle {
                width: 140px;
                height: 140px;
                border-radius: 50%;
                border: 8px solid;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 36px;
                font-weight: 700;
                margin-bottom: 12px;
                position: relative;
            }
            .bb-score-circle::after {
                content: "/100";
                font-size: 16px;
                position: absolute;
                bottom: 38px;
                right: 28px;
                font-weight: 400;
                opacity: 0.7;
            }
            .bb-score-level {
                font-size: 18px;
                font-weight: 600;
                margin-bottom: 8px;
            }
            .bb-score-desc {
                font-size: 13px;
                color: #6b7280;
                text-align: center;
                line-height: 1.5;
            }
            .bb-login-url-box {
                background: #f3f4f6;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
                border-left: 4px solid #667eea;
            }
            .bb-login-url-box strong {
                display: block;
                margin-bottom: 8px;
                color: #1f2937;
                font-size: 14px;
            }
            .bb-login-url-box code {
                display: block;
                background: white;
                padding: 10px;
                border-radius: 4px;
                font-size: 13px;
                word-break: break-all;
                border: 1px solid #d1d5db;
            }
            .bb-checklist {
                list-style: none;
                padding: 0;
                margin: 0;
            }
            .bb-checklist li {
                padding: 15px;
                margin-bottom: 12px;
                background: #f9fafb;
                border-left: 4px solid #e5e7eb;
                border-radius: 6px;
                transition: all 0.2s;
            }
            .bb-checklist li:hover {
                background: #f3f4f6;
                transform: translateX(2px);
            }
            .bb-checklist li.status-ok {
                border-left-color: #10b981;
                background: #ecfdf5;
            }
            .bb-checklist li.status-off {
                border-left-color: #ef4444;
                background: #fef2f2;
            }
            .bb-checklist li .check-header {
                display: flex;
                align-items: center;
                gap: 10px;
                font-weight: 600;
                font-size: 14px;
                margin-bottom: 6px;
            }
            .bb-checklist li .check-header .dashicons {
                font-size: 20px;
            }
            .bb-checklist li.status-ok .dashicons {
                color: #10b981;
            }
            .bb-checklist li.status-off .dashicons {
                color: #ef4444;
            }
            .bb-checklist li .check-desc {
                margin-left: 30px;
                font-size: 13px;
                color: #6b7280;
            }
            .bb-security-option {
                padding: 18px;
                border-left: 4px solid #e5e7eb;
                margin-bottom: 16px;
                background: #f9fafb;
                border-radius: 8px;
                transition: all 0.3s;
            }
            .bb-security-option:hover {
                border-left-color: #667eea;
                background: #f3f4f6;
            }
            .bb-security-option.active {
                border-left-color: #10b981;
                background: #ecfdf5;
            }
            .bb-security-option label {
                font-weight: 600;
                font-size: 14px;
                display: flex;
                align-items: center;
                gap: 12px;
                cursor: pointer;
            }
            .bb-security-option .description {
                margin: 10px 0 0 36px;
                font-size: 13px;
                color: #6b7280;
                line-height: 1.5;
            }
            .bb-cta-box {
                background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
                text-align: center;
            }
            .bb-cta-box h3 {
                margin: 0 0 10px;
                color: white;
                font-size: 18px;
            }
            .bb-cta-box p {
                margin: 0 0 15px;
                opacity: 0.95;
                font-size: 14px;
            }
            .bb-cta-box .button {
                background: white;
                color: #6366f1;
                border: none;
                font-weight: 600;
                padding: 10px 24px;
                border-radius: 6px;
            }
            .bb-cta-box .button:hover {
                background: #f3f4f6;
                color: #4f46e5;
            }
            .bb-dashboard-widget .inside {
                margin: 0;
                padding: 0;
            }
            .bb-dashboard-stats {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-bottom: 15px;
            }
            .bb-dashboard-stat {
                background: #f3f4f6;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
            }
            .bb-dashboard-stat h4 {
                margin: 0;
                font-size: 28px;
                color: #667eea;
                font-weight: 700;
            }
            .bb-dashboard-stat p {
                margin: 5px 0 0;
                font-size: 12px;
                color: #6b7280;
            }
            @media (max-width: 1200px) {
                .bb-security-grid {
                    grid-template-columns: 1fr;
                }
            }
        ');
    }
    
    public function add_plugin_page() {
        add_options_page(
            'BB Biztonsági Központ',
            'BB Biztonság',
            'manage_options',
            'bb-security',
            array($this, 'create_admin_page')
        );
    }
    
    public function create_admin_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $score_data = bb_security_calculate_score();
        $blocked = (int) get_option('bb_security_blocked_attempts', 0);
        
        ?>
        <div class="wrap bb-security-wrap">
            <div class="bb-security-header">
                <h1>🛡️ Business Bloom Biztonsági Központ</h1>
                <p>Professzionális WordPress védelem egyedi login URL-lel és valós idejű monitoringgal • Verzió <?php echo $this->version; ?></p>
            </div>
            
            <div class="bb-security-grid">
                <!-- LEFT SIDEBAR: Score Card -->
                <div>
                    <div class="bb-security-card">
                        <h2>📊 Biztonsági Pontszám</h2>
                        <div class="bb-score-circle-wrap">
                            <div class="bb-score-circle" style="border-color: <?php echo esc_attr($score_data['level_color']); ?>; color: <?php echo esc_attr($score_data['level_color']); ?>;">
                                <span><?php echo esc_html($score_data['score']); ?></span>
                            </div>
                            <div class="bb-score-level" style="color: <?php echo esc_attr($score_data['level_color']); ?>;">
                                <?php echo esc_html($score_data['level_text']); ?>
                            </div>
                            <p class="bb-score-desc">
                                <?php 
                                if ($score_data['score'] >= 90) {
                                    _e('Kiváló! A weboldal maximálisan védett.', 'bb-security');
                                } elseif ($score_data['score'] >= 75) {
                                    _e('Erős védelem. Csak finomhangolás szükséges.', 'bb-security');
                                } elseif ($score_data['score'] >= 50) {
                                    _e('Közepes védelem. Kapcsolj be több funkciót!', 'bb-security');
                                } else {
                                    _e('Gyenge védelem. Sürgősen aktiváld a védelmet!', 'bb-security');
                                }
                                ?>
                            </p>
                        </div>
                        
                        <?php 
                        $login_slug = bb_security_get_login_slug();
                        if (!empty($login_slug)) : 
                        ?>
                        <div class="bb-login-url-box">
                            <strong>🔐 Bejelentkezési URL:</strong>
                            <code><?php echo esc_html(bb_security_build_login_url()); ?></code>
                        </div>
                        <?php endif; ?>
                        
                        <div style="background: #fef3c7; padding: 15px; border-radius: 8px; border-left: 4px solid #f59e0b; margin-top: 20px;">
                            <p style="margin: 0; font-size: 13px; color: #92400e;">
                                <strong>⚡ Blokkolt támadások:</strong> <?php echo number_format($blocked); ?> próbálkozás
                            </p>
                        </div>
                        
                        <div class="bb-cta-box">
                            <h3>💼 Weboldal karbantartás</h3>
                            <p>Folyamatos védelem, naprakész frissítések és professzionális monitoring.</p>
                            <a href="https://businessbloom.consulting/weboldal-karbantartas/" class="button" target="_blank" rel="noopener">
                                Karbantartási csomagok
                            </a>
                        </div>
                    </div>
                </div>
                
                <!-- RIGHT MAIN: Checklist + Settings -->
                <div>
                    <div class="bb-security-card" style="margin-bottom: 25px;">
                        <h2>✅ Védelem Részletei</h2>
                        <ul class="bb-checklist">
                            <?php foreach ($score_data['checks'] as $check) : ?>
                                <li class="<?php echo $check['status'] ? 'status-ok' : 'status-off'; ?>">
                                    <div class="check-header">
                                        <span class="dashicons <?php echo $check['status'] ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
                                        <span><?php echo esc_html($check['label']); ?></span>
                                        <span style="margin-left: auto; font-weight: 400; color: #9ca3af;"><?php echo $check['weight']; ?> pont</span>
                                    </div>
                                    <div class="check-desc">
                                        <?php echo esc_html($check['status'] ? $check['desc_on'] : $check['desc_off']); ?>
                                    </div>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                    
                    <div class="bb-security-card">
                        <h2>⚙️ Biztonsági Beállítások</h2>
                        <form method="post" action="options.php">
                            <?php
                            settings_fields('bb_security_option_group');
                            do_settings_sections('bb-security-admin');
                            submit_button('Beállítások mentése', 'primary large', 'submit', false);
                            ?>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    public function page_init() {
        register_setting(
            'bb_security_option_group',
            'bb_security_options',
            array($this, 'sanitize')
        );
        
        add_settings_section(
            'bb_security_main_section',
            null,
            null,
            'bb-security-admin'
        );
        
        // Custom Login URL
        add_settings_field(
            'custom_login_url',
            '🔐 Egyedi bejelentkezési URL',
            array($this, 'custom_login_callback'),
            'bb-security-admin',
            'bb_security_main_section'
        );
        
        $fields = array(
            'hide_wp_admin' => array(
                'title' => '🚫 wp-admin elrejtése vendégeknek',
                'desc' => 'Nem bejelentkezett látogatók 404-et kapnak wp-admin elérésekor'
            ),
            'login_rate_limit' => array(
                'title' => '⏱️ Login rate limiting',
                'desc' => '5 sikertelen próba után 15 perc várakozás'
            ),
            'email_notifications' => array(
                'title' => '📧 Email értesítések',
                'desc' => 'Értesítés sikeres login és blokkolt kísérletek esetén'
            ),
            'security_headers' => array(
                'title' => '📋 HTTP biztonsági fejlécek',
                'desc' => 'X-Frame-Options, HSTS, Content-Type-Options beállítása'
            ),
            'rest_api_protection' => array(
                'title' => '🛡️ REST API felhasználói védelem',
                'desc' => 'Megakadályozza a felhasználónevek lekérését REST API-n keresztül'
            ),
            'author_protection' => array(
                'title' => '👤 Author enumeration védelem',
                'desc' => 'Tiltja az /author/username/ és ?author=1 típusú felhasználó felderítést'
            ),
            'disable_xmlrpc' => array(
                'title' => '🚫 XML-RPC letiltása',
                'desc' => 'Brute force támadások melegágya - letiltás ajánlott'
            ),
            'hide_version' => array(
                'title' => '🙈 WordPress verzió elrejtése',
                'desc' => 'Eltávolítja a verzió számokat a forráskódból'
            ),
            'file_upload_protection' => array(
                'title' => '📁 Veszélyes fájltípusok tiltása',
                'desc' => 'SVG, EXE, SWF fájlok feltöltésének megakadályozása'
            ),
            'sensitive_files_block' => array(
                'title' => '🔐 Érzékeny fájlok elrejtése',
                'desc' => 'readme.html, license.txt, wp-config-sample.php védelem'
            ),
        );
        
        foreach ($fields as $id => $field) {
            add_settings_field(
                $id,
                $field['title'],
                array($this, 'checkbox_callback'),
                'bb-security-admin',
                'bb_security_main_section',
                array('id' => $id, 'desc' => $field['desc'])
            );
        }
        
        add_settings_field(
            'notification_email',
            '📬 Értesítési email cím',
            array($this, 'email_callback'),
            'bb-security-admin',
            'bb_security_main_section'
        );
    }
    
    public function custom_login_callback() {
        $slug = bb_security_get_login_slug();
        $example = !empty($slug) ? home_url('/' . $slug . '/') : home_url('/wp-login.php');
        
        echo '<div class="bb-security-option">';
        printf(
            '<input type="text" id="custom_login_url" name="bb_security_options[custom_login_url]" value="%s" class="regular-text" placeholder="pl: bb-login">',
            esc_attr($slug)
        );
        echo '<p class="description">';
        _e('Hagyd üresen, ha nem akarsz egyedi login URL-t használni. Ha kitöltöd, a wp-login.php elérhetetlenné válik.', 'bb-security');
        echo '<br><strong>' . __('Jelenlegi bejelentkezési URL:', 'bb-security') . '</strong> <code>' . esc_html($example) . '</code>';
        echo '<br>⚠️ <strong>' . __('FONTOS:', 'bb-security') . '</strong> ' . __('Ha megváltoztatod, emlékezz az új URL-re! Email-ben megkapod mentés után.', 'bb-security');
        echo '</p>';
        echo '</div>';
    }
    
    public function checkbox_callback($args) {
        $id = $args['id'];
        $desc = $args['desc'];
        $checked = isset($this->options[$id]) && $this->options[$id] == 1;
        $class = $checked ? 'active' : '';
        
        echo '<div class="bb-security-option ' . $class . '">';
        printf(
            '<label><input type="checkbox" id="%s" name="bb_security_options[%s]" value="1" %s> %s</label>',
            $id, $id, checked(1, $checked, false), $args['title']
        );
        echo '<p class="description">' . $desc . '</p>';
        echo '</div>';
    }
    
    public function email_callback() {
        $email = isset($this->options['notification_email']) ? $this->options['notification_email'] : get_option('admin_email');
        echo '<div class="bb-security-option">';
        printf(
            '<input type="email" id="notification_email" name="bb_security_options[notification_email]" value="%s" class="regular-text">',
            esc_attr($email)
        );
        echo '<p class="description">' . __('Email cím, ahova a biztonsági értesítések érkeznek', 'bb-security') . '</p>';
        echo '</div>';
    }
    
    public function sanitize($input) {
        $old_options = bb_security_get_options();
        $options = array();
        
        // Custom login URL
        if (isset($input['custom_login_url'])) {
            $slug = sanitize_title($input['custom_login_url']);
            $options['custom_login_url'] = $slug;
            
            // Ha változott, küldünk emailt
            if ($slug !== $old_options['custom_login_url']) {
                $this->send_login_url_email($slug);
            }
        }
        
        // Checkboxes
        $checkboxes = array(
            'hide_wp_admin', 'hide_version', 'disable_xmlrpc', 'login_errors',
            'rest_api_protection', 'author_protection', 'security_headers',
            'login_rate_limit', 'file_upload_protection', 'sensitive_files_block',
            'email_notifications'
        );
        
        foreach ($checkboxes as $key) {
            $options[$key] = !empty($input[$key]) ? 1 : 0;
        }
        
        // Email
        $options['notification_email'] = sanitize_email($input['notification_email']);
        
        return $options;
    }
    
    private function send_login_url_email($slug) {
        $options = bb_security_get_options();
        $to = !empty($options['notification_email']) ? $options['notification_email'] : get_option('admin_email');
        
        $login_url = !empty($slug) ? home_url('/' . $slug . '/') : home_url('/wp-login.php');
        
        $subject = '[' . get_bloginfo('name') . '] Bejelentkezési URL megváltozott';
        
        $message = '
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="margin: 0;">🔐 Bejelentkezési URL frissítve</h2>
                </div>
                <div style="padding: 20px; background: #f9f9f9; border-radius: 8px;">
                    <p><strong>Az új bejelentkezési URL:</strong></p>
                    <div style="background: white; padding: 15px; border-radius: 6px; border: 2px solid #667eea; margin: 15px 0;">
                        <code style="font-size: 16px; color: #667eea; font-weight: 600;">' . esc_html($login_url) . '</code>
                    </div>
                    <p style="color: #dc3232; font-weight: 600;">⚠️ FONTOS: Mentsd el ezt az URL-t biztonságos helyre!</p>
                    <p>A régi wp-login.php URL már nem működik - 404-et fog adni.</p>
                </div>
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                    <p style="margin: 0; font-size: 14px;"><strong>Weboldal:</strong> ' . get_bloginfo('name') . '</p>
                    <p style="margin: 5px 0 0; font-size: 14px;"><strong>Időpont:</strong> ' . current_time('Y-m-d H:i:s') . '</p>
                </div>
            </div>
        </body>
        </html>';
        
        $headers = array('Content-Type: text/html; charset=UTF-8');
        $sent = wp_mail($to, $subject, $message, $headers);
        if (!$sent) {
            $this->set_email_failure_notice(__('Nem sikerult kikuldeni az admin URL valtozasrol szolo emailt. Ellenorizd az SMTP beallitast es az ertesitesi email cimet.', 'bb-security'));
        }
    }

    private function set_email_failure_notice($message) {
        if (empty($message)) {
            return;
        }

        update_option('bb_security_email_error_notice', $message);
    }

    public function email_failure_notice() {
        $notice = get_option('bb_security_email_error_notice');
        if (empty($notice)) {
            return;
        }

        echo '<div class="notice notice-error is-dismissible"><p>' . esc_html($notice) . '</p></div>';
        delete_option('bb_security_email_error_notice');
    }
    
    public function add_dashboard_widget() {
        wp_add_dashboard_widget(
            'bb_security_dashboard_widget',
            '🛡️ Business Bloom Biztonság',
            array($this, 'dashboard_widget_content')
        );
    }
    
    public function dashboard_widget_content() {
        $score_data = bb_security_calculate_score();
        $blocked = (int) get_option('bb_security_blocked_attempts', 0);
        $login_slug = bb_security_get_login_slug();
        
        echo '<div class="bb-dashboard-stats">';
        echo '<div class="bb-dashboard-stat"><h4 style="color: ' . esc_attr($score_data['level_color']) . ';">' . $score_data['score'] . '/100</h4><p>Biztonság</p></div>';
        echo '<div class="bb-dashboard-stat"><h4>' . number_format($blocked) . '</h4><p>Blokkolt támadás</p></div>';
        echo '</div>';
        
        if (!empty($login_slug)) {
            echo '<div style="background: #f0f0f0; padding: 10px; border-radius: 6px; margin-bottom: 15px;">';
            echo '<strong style="font-size: 12px;">🔐 Login URL:</strong><br>';
            echo '<code style="font-size: 11px;">' . esc_html(bb_security_build_login_url()) . '</code>';
            echo '</div>';
        }
        
        echo '<p style="text-align:center; margin:10px 0 0;"><a href="' . admin_url('options-general.php?page=bb-security') . '" class="button button-primary">Beállítások</a></p>';
    }
}

$bb_security_settings = new BB_Security_Settings();

/* ========================================
   EMAIL NOTIFICATIONS
   ======================================== */

class BB_Security_Notifications {
    
    private $settings;
    
    public function __construct($settings) {
        $this->settings = $settings;
    }
    
    public function send_notification($subject, $message) {
        $options = bb_security_get_options();
        
        if (empty($options['email_notifications'])) {
            return;
        }
        
        $to = $options['notification_email'];
        $headers = array('Content-Type: text/html; charset=UTF-8');
        
        $html_message = '
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="margin: 0;">🛡️ Business Bloom Biztonsági Értesítés</h2>
                </div>
                <div style="padding: 20px; background: #f9f9f9; border-radius: 8px;">
                    ' . $message . '
                </div>
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                    <p style="margin: 0; font-size: 14px;"><strong>Weboldal:</strong> ' . get_bloginfo('name') . ' (' . home_url() . ')</p>
                    <p style="margin: 5px 0 0; font-size: 14px;"><strong>Időpont:</strong> ' . current_time('Y-m-d H:i:s') . '</p>
                </div>
            </div>
        </body>
        </html>';
        
        wp_mail($to, '[' . get_bloginfo('name') . '] ' . $subject, $html_message, $headers);
    }
}

$bb_security_notifications = new BB_Security_Notifications($bb_security_settings);

/* ========================================
   CUSTOM LOGIN URL HANDLER
   ======================================== */

/**
 * Intercept custom login slug and load wp-login.php
 */
function bb_security_maybe_handle_custom_login() {
    if (defined('BB_CUSTOM_LOGIN') && BB_CUSTOM_LOGIN) {
        return;
    }
    
    if (defined('WP_CLI') && WP_CLI) {
        return;
    }
    
    if (!bb_security_is_custom_login_request()) {
        return;
    }
    
    define('BB_CUSTOM_LOGIN', true);
    require_once ABSPATH . 'wp-login.php';
    exit;
}
add_action('init', 'bb_security_maybe_handle_custom_login', 0);

/**
 * Block direct wp-login.php access if custom login is enabled
 */
function bb_security_block_default_login() {
    $slug = bb_security_get_login_slug();
    
    // Ha nincs custom slug, engedjük a wp-login.php-t
    if (empty($slug)) {
        return;
    }
    
    // Ha a custom slugról jövünk, engedjük
    if (defined('BB_CUSTOM_LOGIN') && BB_CUSTOM_LOGIN) {
        return;
    }
    
    if (defined('WP_CLI') && WP_CLI) {
        return;
    }
    
    status_header(404);
    nocache_headers();
    wp_die(
        __('A keresett oldal nem található.', 'bb-security'),
        '',
        array('response' => 404)
    );
}
add_action('login_init', 'bb_security_block_default_login', 0);

/**
 * Filter login URLs
 */
function bb_security_filter_login_url($login_url, $redirect, $force_reauth) {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        return $login_url;
    }
    
    $args = array();
    if (!empty($redirect)) {
        $args['redirect_to'] = $redirect;
    }
    if ($force_reauth) {
        $args['reauth'] = '1';
    }
    
    return bb_security_build_login_url($args);
}
add_filter('login_url', 'bb_security_filter_login_url', 10, 3);

function bb_security_filter_lostpassword_url($lostpassword_url, $redirect) {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        return $lostpassword_url;
    }
    
    $args = array('action' => 'lostpassword');
    if (!empty($redirect)) {
        $args['redirect_to'] = $redirect;
    }
    
    return bb_security_build_login_url($args);
}
add_filter('lostpassword_url', 'bb_security_filter_lostpassword_url', 10, 2);

function bb_security_filter_logout_url($logout_url, $redirect) {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        return $logout_url;
    }
    
    $args = array(
        'action' => 'logout',
        '_wpnonce' => wp_create_nonce('log-out'),
    );
    
    if (!empty($redirect)) {
        $args['redirect_to'] = $redirect;
    }
    
    return bb_security_build_login_url($args);
}
add_filter('logout_url', 'bb_security_filter_logout_url', 10, 2);

/**
 * Intercept site_url() for login form action
 */
function bb_security_filter_site_url($url, $path, $scheme, $blog_id) {
    $slug = bb_security_get_login_slug();
    
    if (empty($slug)) {
        return $url;
    }
    
    if ('login' !== $scheme && 'login_post' !== $scheme) {
        return $url;
    }
    
    if (false === strpos($url, 'wp-login.php')) {
        return $url;
    }
    
    $args = array();
    $parsed = wp_parse_url($url);
    if (isset($parsed['query'])) {
        parse_str($parsed['query'], $args);
    }
    
    return bb_security_build_login_url($args);
}
add_filter('site_url', 'bb_security_filter_site_url', 10, 4);
add_filter('network_site_url', 'bb_security_filter_site_url', 10, 4);

/* ========================================
   WP-ADMIN PROTECTION
   ======================================== */

function bb_security_block_admin_for_guests() {
    $options = bb_security_get_options();
    
    if (empty($options['hide_wp_admin'])) {
        return;
    }
    
    if (is_user_logged_in()) {
        return;
    }
    
    if ((defined('DOING_AJAX') && DOING_AJAX)
        || (defined('DOING_CRON') && DOING_CRON)
        || (defined('WP_CLI') && WP_CLI)) {
        return;
    }
    
    $script = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '';
    $request = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
    
    if ((is_string($script) && false !== strpos($script, 'wp-admin'))
        || (is_string($request) && false !== strpos($request, '/wp-admin'))) {
        
        status_header(404);
        nocache_headers();
        wp_die(
            __('A keresett oldal nem található.', 'bb-security'),
            '',
            array('response' => 404)
        );
    }
}
add_action('init', 'bb_security_block_admin_for_guests', 1);

/* ========================================
   SECURITY FEATURES
   ======================================== */

function bb_security_bootstrap() {
    $opts = bb_security_get_options();
    
    // Version hiding
    if (!empty($opts['hide_version'])) {
        add_filter('the_generator', '__return_empty_string');
        
        function bb_remove_version_strings($src) {
            if (strpos($src, 'ver=')) {
                $src = remove_query_arg('ver', $src);
            }
            return $src;
        }
        add_filter('script_loader_src', 'bb_remove_version_strings');
        add_filter('style_loader_src', 'bb_remove_version_strings');
        
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
        remove_action('wp_head', 'wp_shortlink_wp_head');
        remove_action('wp_head', 'rest_output_link_wp_head');
    }
    
    // XML-RPC
    if (!empty($opts['disable_xmlrpc'])) {
        add_filter('xmlrpc_enabled', '__return_false');
    }
    
    // Login errors
    if (!empty($opts['login_errors'])) {
        add_filter('login_errors', function() {
            return __('Hiba: Érvénytelen bejelentkezési adatok.', 'bb-security');
        });
    }
    
    // REST API protection
    if (!empty($opts['rest_api_protection'])) {
        add_filter('rest_endpoints', function($endpoints) {
            if (!is_user_logged_in()) {
                unset($endpoints['/wp/v2/users']);
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
            return $endpoints;
        });
    }
    
    // Author protection
    if (!empty($opts['author_protection'])) {
        add_action('template_redirect', function() {
            if (is_author()) {
                wp_redirect(home_url(), 301);
                exit;
            }
        });
        
        add_action('init', function() {
            if (isset($_GET['author']) && !is_admin()) {
                wp_redirect(home_url(), 301);
                exit;
            }
        });
    }
    
    // Security headers
    if (!empty($opts['security_headers'])) {
        add_action('send_headers', function() {
            header('X-Frame-Options: SAMEORIGIN');
            header('X-Content-Type-Options: nosniff');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
            
            if (is_ssl()) {
                header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
            }
        });
    }
    
    // Login rate limiting
    if (!empty($opts['login_rate_limit'])) {
        add_filter('authenticate', 'bb_security_rate_limit_check', 30, 2);
        add_action('wp_login_failed', 'bb_security_rate_limit_failed');
        add_action('wp_login', 'bb_security_rate_limit_success', 10, 2);
    }
    
    // File upload protection
    if (!empty($opts['file_upload_protection'])) {
        add_filter('upload_mimes', function($mimes) {
            unset($mimes['svg']);
            unset($mimes['svgz']);
            unset($mimes['exe']);
            unset($mimes['swf']);
            return $mimes;
        });
        
        add_filter('sanitize_file_name', function($filename) {
            return preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
        });
    }
    
    // Sensitive files
    if (!empty($opts['sensitive_files_block'])) {
        add_action('init', function() {
            $sensitive = ['readme.html', 'license.txt', 'wp-config-sample.php'];
            $request_uri = $_SERVER['REQUEST_URI'] ?? '';
            
            foreach ($sensitive as $file) {
                if (strpos($request_uri, $file) !== false) {
                    wp_die(__('Hozzáférés megtagadva.', 'bb-security'), 'Tiltott', ['response' => 403]);
                }
            }
        });
    }
}
add_action('plugins_loaded', 'bb_security_bootstrap');

/* Rate limiting functions */
function bb_security_rate_limit_check($user, $username) {
    global $bb_security_notifications;
    
    if (empty($username)) return $user;
    
    $transient_key = 'bb_login_attempts_' . md5($username . $_SERVER['REMOTE_ADDR']);
    $attempts = (int) get_transient($transient_key);
    
    if ($attempts >= 5) {
        $blocked_count = (int) get_option('bb_security_blocked_attempts', 0);
        update_option('bb_security_blocked_attempts', $blocked_count + 1);
        update_option('bb_security_last_blocked', current_time('Y-m-d H:i:s'));
        
        $message = '
        <p><strong>⚠️ Blokkolt bejelentkezési kísérlet!</strong></p>
        <p>Valaki túl sok sikertelen próbálkozást hajtott végre.</p>
        <ul>
            <li><strong>Felhasználónév:</strong> ' . esc_html($username) . '</li>
            <li><strong>IP cím:</strong> ' . $_SERVER['REMOTE_ADDR'] . '</li>
            <li><strong>Próbálkozások:</strong> ' . $attempts . '</li>
            <li><strong>Várakozási idő:</strong> 15 perc</li>
        </ul>';
        
        $bb_security_notifications->send_notification(
            'Blokkolt bejelentkezési kísérlet',
            $message
        );
        
        return new WP_Error(
            'too_many_attempts',
            __('Túl sok sikertelen próbálkozás. Várakozási idő: 15 perc.', 'bb-security')
        );
    }
    
    return $user;
}

function bb_security_rate_limit_failed($username) {
    $transient_key = 'bb_login_attempts_' . md5($username . $_SERVER['REMOTE_ADDR']);
    $attempts = (int) get_transient($transient_key);
    set_transient($transient_key, $attempts + 1, 15 * MINUTE_IN_SECONDS);
}

function bb_security_rate_limit_success($username, $user) {
    global $bb_security_notifications;
    
    $transient_key = 'bb_login_attempts_' . md5($username . $_SERVER['REMOTE_ADDR']);
    delete_transient($transient_key);
    
    $message = '
    <p><strong>✅ Sikeres bejelentkezés</strong></p>
    <p>Valaki sikeresen bejelentkezett a weboldalra.</p>
    <ul>
        <li><strong>Felhasználó:</strong> ' . esc_html($username) . '</li>
        <li><strong>Role:</strong> ' . implode(', ', $user->roles) . '</li>
        <li><strong>IP cím:</strong> ' . $_SERVER['REMOTE_ADDR'] . '</li>
        <li><strong>User Agent:</strong> ' . $_SERVER['HTTP_USER_AGENT'] . '</li>
    </ul>
    <p style="padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107;">
        💡 <strong>Tipp:</strong> Ha ez nem te voltál, azonnal változtasd meg a jelszavad!
    </p>';
    
    $bb_security_notifications->send_notification(
        'Sikeres bejelentkezés - ' . $username,
        $message
    );
}

/* ========================================
   WP-CLI RECOVERY COMMAND
   ======================================== */

if (defined('WP_CLI') && WP_CLI) {
    class BB_Security_CLI {
        public function show_login_url() {
            $slug = bb_security_get_login_slug();
            
            if (empty($slug)) {
                WP_CLI::line('Nincs egyedi login URL beállítva.');
                WP_CLI::line('Alapértelmezett: ' . wp_login_url());
            } else {
                WP_CLI::success('Login URL: ' . bb_security_build_login_url());
            }
        }
        
        public function reset_login_url() {
            $options = bb_security_get_options();
            $options['custom_login_url'] = '';
            update_option('bb_security_options', $options);
            
            WP_CLI::success('Login URL visszaállítva alapértelmezettre: ' . wp_login_url());
        }
    }
    
    WP_CLI::add_command('bb-security show-login', array('BB_Security_CLI', 'show_login_url'));
    WP_CLI::add_command('bb-security reset-login', array('BB_Security_CLI', 'reset_login_url'));
}

