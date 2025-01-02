<?php

declare(strict_types=1);

require_once __DIR__ . '/../libs/common.php';
require_once __DIR__ . '/../libs/local.php';

class AdGuardHome extends IPSModule
{
    use AdGuardHome\StubsCommonLib;
    use AdGuardHomeLocalLib;

    public function __construct(string $InstanceID)
    {
        parent::__construct($InstanceID);

        $this->CommonConstruct(__DIR__);
    }

    public function __destruct()
    {
        $this->CommonDestruct();
    }

    public function Create()
    {
        parent::Create();

        $this->RegisterPropertyBoolean('module_disable', false);

        $this->RegisterPropertyString('host', '');
        $this->RegisterPropertyBoolean('use_https', false);
        $this->RegisterPropertyString('user', '');
        $this->RegisterPropertyString('password', '');

        $this->RegisterPropertyInteger('update_interval', 60);

        $this->RegisterAttributeString('UpdateInfo', json_encode([]));
        $this->RegisterAttributeString('ModuleStats', json_encode([]));

        $this->InstallVarProfiles(false);

        $this->RegisterTimer('UpdateStatus', 0, 'IPS_RequestAction(' . $this->InstanceID . ', "UpdateStatus", "");');

        $this->RegisterMessage(0, IPS_KERNELMESSAGE);
    }

    public function MessageSink($timestamp, $senderID, $message, $data)
    {
        parent::MessageSink($timestamp, $senderID, $message, $data);

        if ($message == IPS_KERNELMESSAGE && $data[0] == KR_READY) {
            $this->SetUpdateInterval();
        }
    }

    private function CheckModuleConfiguration()
    {
        $r = [];

        $host = $this->ReadPropertyString('host');
        if ($host == '') {
            $this->SendDebug(__FUNCTION__, '"host" is needed', 0);
            $r[] = $this->Translate('Host must be specified');
        }
        $user = $this->ReadPropertyString('user');
        if ($user == '') {
            $this->SendDebug(__FUNCTION__, '"user" is needed', 0);
            $r[] = $this->Translate('Username must be specified');
        }

        $password = $this->ReadPropertyString('password');
        if ($password == '') {
            $this->SendDebug(__FUNCTION__, '"password" is needed', 0);
            $r[] = $this->Translate('Password must be specified');
        }

        return $r;
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        $this->MaintainReferences();

        if ($this->CheckPrerequisites() != false) {
            $this->MaintainTimer('UpdateStatus', 0);
            $this->MaintainStatus(self::$IS_INVALIDPREREQUISITES);
            return;
        }

        if ($this->CheckUpdate() != false) {
            $this->MaintainTimer('UpdateStatus', 0);
            $this->MaintainStatus(self::$IS_UPDATEUNCOMPLETED);
            return;
        }

        if ($this->CheckConfiguration() != false) {
            $this->MaintainTimer('UpdateStatus', 0);
            $this->MaintainStatus(self::$IS_INVALIDCONFIG);
            return;
        }

        $vpos = 0;
        $this->MaintainVariable('protection_enabled', $this->Translate('Protection enabled'), VARIABLETYPE_BOOLEAN, '~Switch', $vpos++, true);
        $this->MaintainAction('protection_enabled', true);

        $vpos = 10;
        $this->MaintainVariable('total_dns_queries', $this->Translate('DNS requests (total)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('total_blocked', $this->Translate('Blocked addresses (total)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('total_rate', $this->Translate('Blocking rate (total)'), VARIABLETYPE_FLOAT, 'AdGuardHome.Rate', $vpos++, true);

        $vpos = 20;
        $this->MaintainVariable('today_dns_queries', $this->Translate('DNS requests (today)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('today_blocked', $this->Translate('Blocked addresses (today)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('today_rate', $this->Translate('Blocking rate (today)'), VARIABLETYPE_FLOAT, 'AdGuardHome.Rate', $vpos++, true);

        $vpos = 30;
        $this->MaintainVariable('daily_dns_queries', $this->Translate('DNS requests (daily)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('daily_blocked', $this->Translate('Blocked addresses (daily)'), VARIABLETYPE_INTEGER, '', $vpos++, true);
        $this->MaintainVariable('daily_rate', $this->Translate('Blocking rate (daily)'), VARIABLETYPE_FLOAT, 'AdGuardHome.Rate', $vpos++, true);

        $vpos = 50;
        $this->MaintainVariable('average_time', $this->Translate('Average processing time'), VARIABLETYPE_FLOAT, 'AdGuardHome.ms', $vpos++, true);

        $vpos = 90;
        $this->MaintainVariable('filter_update', $this->Translate('Oldest filter update'), VARIABLETYPE_INTEGER, '~UnixTimestamp', $vpos++, true);

        $vpos = 100;
        $this->MaintainVariable('LastUpdate', $this->Translate('Last update'), VARIABLETYPE_INTEGER, '~UnixTimestamp', $vpos++, true);

        $module_disable = $this->ReadPropertyBoolean('module_disable');
        if ($module_disable) {
            $this->MaintainTimer('UpdateStatus', 0);
            $this->MaintainStatus(IS_INACTIVE);
            return;
        }

        $this->MaintainStatus(IS_ACTIVE);

        if (IPS_GetKernelRunlevel() == KR_READY) {
            $this->SetUpdateInterval();
        }
    }

    private function GetFormElements()
    {
        $formElements = $this->GetCommonFormElements('AdGuard Home');

        if ($this->GetStatus() == self::$IS_UPDATEUNCOMPLETED) {
            return $formElements;
        }

        $formElements[] = [
            'type'    => 'CheckBox',
            'name'    => 'module_disable',
            'caption' => 'Disable instance'
        ];

        $formElements[] = [
            'type'    => 'ExpansionPanel',
            'items'   => [
                [
                    'type'    => 'ValidationTextBox',
                    'name'    => 'host',
                    'caption' => 'Host'
                ],
                [
                    'type'    => 'CheckBox',
                    'name'    => 'use_https',
                    'caption' => 'Use HTTPS'
                ],
                [
                    'type'    => 'ValidationTextBox',
                    'name'    => 'user',
                    'caption' => 'User'
                ],
                [
                    'type'    => 'PasswordTextBox',
                    'name'    => 'password',
                    'caption' => 'Password'
                ],
            ],
            'caption' => 'Access configuration',
        ];

        $formElements[] = [
            'type'    => 'NumberSpinner',
            'name'    => 'update_interval',
            'suffix'  => 'Seconds',
            'minimum' => 0,
            'caption' => 'Update interval',
        ];

        return $formElements;
    }

    private function GetFormActions()
    {
        $formActions = [];

        if ($this->GetStatus() == self::$IS_UPDATEUNCOMPLETED) {
            $formActions[] = $this->GetCompleteUpdateFormAction();

            $formActions[] = $this->GetInformationFormAction();
            $formActions[] = $this->GetReferencesFormAction();

            return $formActions;
        }

        $formActions[] = [
            'type'    => 'Button',
            'caption' => 'Update status',
            'onClick' => 'IPS_RequestAction($id, "UpdateStatus", "");',
        ];

        $formActions[] = [
            'type'      => 'ExpansionPanel',
            'caption'   => 'Expert area',
            'expanded'  => false,
            'items'     => [
                $this->GetInstallVarProfilesFormItem(),
            ],
        ];

        $formActions[] = [
            'type'      => 'ExpansionPanel',
            'caption'   => 'Test area',
            'expanded'  => false,
            'items'     => [
                [
                    'type'    => 'TestCenter',
                ],
            ]
        ];

        $formActions[] = $this->GetInformationFormAction();
        $formActions[] = $this->GetReferencesFormAction();

        return $formActions;
    }

    private function SetUpdateInterval(int $sec = null)
    {
        $sec = $this->ReadPropertyInteger('update_interval');
        $this->MaintainTimer('UpdateStatus', $sec * 1000);
    }

    public function SwitchEnableProtection(bool $mode)
    {
        if ($this->CheckStatus() == self::$STATUS_INVALID) {
            $this->SendDebug(__FUNCTION__, $this->GetStatusText() . ' => skip', 0);
            return false;
        }

        $postdata = [
            'protection_enabled' => $mode,
        ];

        $data = '';
        $statuscode = $this->do_HttpRequest('dns_config', '', $postdata, 'POST', $data);
        if ($statuscode != 0) {
            $this->MaintainStatus($statuscode);
            return false;
        }
        return true;
    }

    private function LocalRequestAction($ident, $value)
    {
        $r = true;
        switch ($ident) {
            case 'UpdateStatus':
                $this->UpdateStatus();
                break;
            default:
                $r = false;
                break;
        }
        return $r;
    }

    public function RequestAction($ident, $value)
    {
        if ($this->LocalRequestAction($ident, $value)) {
            return;
        }
        if ($this->CommonRequestAction($ident, $value)) {
            return;
        }

        if ($this->GetStatus() == IS_INACTIVE) {
            $this->SendDebug(__FUNCTION__, $this->GetStatusText() . ' => skip', 0);
            return;
        }

        $this->SendDebug(__FUNCTION__, 'ident=' . $ident . ', value=' . $value, 0);

        $r = false;
        switch ($ident) {
            case 'protection_enabled':
                $r = $this->SwitchEnableProtection((bool) $value);
                $this->SendDebug(__FUNCTION__, $ident . '=' . $this->bool2str($value) . ' => ret=' . $this->bool2str($r), 0);
                break;
            default:
                $this->SendDebug(__FUNCTION__, 'invalid ident ' . $ident, 0);
                break;
        }
        if ($r) {
            $this->SetValue($ident, $value);
        }
    }

    private function UpdateStatus()
    {
        if ($this->CheckStatus() == self::$STATUS_INVALID) {
            $this->SendDebug(__FUNCTION__, $this->GetStatusText() . ' => skip', 0);
            return;
        }

        $data = '';
        $statuscode = $this->do_HttpRequest('status', '', '', 'GET', $data);
        if ($statuscode != 0) {
            $this->MaintainStatus($statuscode);
            return;
        }
        $jdata = json_decode($data, true);
        $this->SendDebug(__FUNCTION__, 'status=' . print_r($jdata, true), 0);
        /*
            status=Array
            (
                [dns_addresses] => Array
                [dns_port] => 53
                [http_port] => 80
                [protection_enabled] => 1
                [dhcp_available] => 1
                [running] => 1
                [version] => v0.107.7
                [language] => de
            )
         */
        $protection_enabled = (bool) $this->GetArrayElem($jdata, 'protection_enabled', 0);
        $this->SetValue('protection_enabled', $protection_enabled);

        /*
            dns_info=Array
            (
                [upstream_dns] => Array
                [upstream_dns_file] =>
                [bootstrap_dns] => Array
                [protection_enabled] => 1
                [ratelimit] => 20
                [blocking_mode] => default
                [blocking_ipv4] =>
                [blocking_ipv6] =>
                [edns_cs_enabled] => 1
                [dnssec_enabled] => 1
                [disable_ipv6] => 1
                [upstream_mode] => parallel
                [cache_size] => 4194304
                [cache_ttl_min] => 0
                [cache_ttl_max] => 10
                [cache_optimistic] =>
                [resolve_clients] => 1
                [use_private_ptr_resolvers] => 1
                [local_ptr_upstreams] => Array
                [default_local_ptr_upstreams] => Array
            )
         */

        $data = '';
        $statuscode = $this->do_HttpRequest('stats', '', '', 'GET', $data);
        if ($statuscode != 0) {
            $this->MaintainStatus($statuscode);
            return;
        }
        $jdata = json_decode($data, true);
        $this->SendDebug(__FUNCTION__, 'stats=' . print_r($jdata, true), 0);
        /*
            stats=Array
            (
                [time_units] => days
                [num_dns_queries] => 2954909
                [num_blocked_filtering] => 164016
                [num_replaced_safebrowsing] => 14
                [num_replaced_safesearch] => 0
                [num_replaced_parental] => 0
                [avg_processing_time] => 0,018805
                [top_queried_domains] => Array
                [top_clients] => Array
                [top_blocked_domains] => Array
                [dns_queries] => Array
                [blocked_filtering] => Array
                [replaced_safebrowsing] => Array
                [replaced_parental] => Array
            )
         */

        $total_dns_queries = (int) $this->GetArrayElem($jdata, 'num_dns_queries', 0);

        $daily_dns_queries = 0;
        $today_dns_queries = 0;
        if (isset($jdata['dns_queries'])) {
            $dns_queries = $jdata['dns_queries'];
            if (is_array($dns_queries)) {
                for ($i = 0, $n = 0, $v = 0; $i < count($dns_queries); $i++) {
                    if ($dns_queries[$i] == 0) {
                        continue;
                    }
                    $n++;
                    $v += $dns_queries[$i];
                }
                if ($v && $n) {
                    $daily_dns_queries = floor($v / $n);
                }
                $today_dns_queries = $dns_queries[count($dns_queries) - 1];
            }
        }
        $this->SendDebug(__FUNCTION__, 'dns_queries total=' . $total_dns_queries . ', daily=' . $daily_dns_queries . ', today=' . $today_dns_queries, 0);

        $total_blocked = 0;
        foreach (['num_blocked_filtering', 'num_replaced_safebrowsing', 'num_replaced_parental'] as $f) {
            if (isset($jdata[$f])) {
                $total_blocked += (int) $jdata[$f];
            }
        }

        $daily_blocked = 0;
        $today_blocked = 0;
        foreach (['blocked_filtering', 'replaced_safebrowsing', 'replaced_parental'] as $f) {
            if (isset($jdata[$f])) {
                $blocked = $jdata[$f];
                if (is_array($blocked)) {
                    for ($i = 0, $n = 0, $v = 0; $i < count($blocked); $i++) {
                        if ($blocked[$i] == 0) {
                            continue;
                        }
                        $n++;
                        $v += $blocked[$i];
                    }
                    if ($v && $n) {
                        $daily_blocked += floor($v / $n);
                    }
                    $today_blocked += $blocked[count($blocked) - 1];
                }
            }
        }
        $this->SendDebug(__FUNCTION__, 'blocked total=' . $total_blocked . ',daily=' . $daily_blocked . ', today=' . $today_blocked, 0);

        $total_rate = $total_dns_queries > 0 ? $total_blocked * 100.0 / $total_dns_queries : 0;
        $today_rate = $today_dns_queries > 0 ? $today_blocked * 100.0 / $today_dns_queries : 0;
        $daily_rate = $daily_dns_queries > 0 ? $daily_blocked * 100.0 / $daily_dns_queries : 0;

        $this->SetValue('total_dns_queries', $total_dns_queries);
        $this->SetValue('total_blocked', $total_blocked);
        $this->SetValue('total_rate', $total_rate);

        $this->SetValue('today_dns_queries', $today_dns_queries);
        $this->SetValue('today_blocked', $today_blocked);
        $this->SetValue('today_rate', $today_rate);

        $this->SetValue('daily_dns_queries', $daily_dns_queries);
        $this->SetValue('daily_blocked', $daily_blocked);
        $this->SetValue('daily_rate', $daily_rate);

        $avg_processing_time = (float) $this->GetArrayElem($jdata, 'avg_processing_time', 0);
        $this->SetValue('average_time', $avg_processing_time * 1000);

        $data = '';
        $statuscode = $this->do_HttpRequest('filtering/status', '', '', 'GET', $data);
        if ($statuscode != 0) {
            $this->MaintainStatus($statuscode);
            return;
        }
        $jdata = json_decode($data, true);
        $this->SendDebug(__FUNCTION__, 'filtering/status=' . print_r($jdata, true), 0);
        /*
            filtering/status=Array
            (
                [enabled] => 1
                [interval] => 24
                [filters] => Array
                    (
                        [0] => Array
                            (
                                [enabled] => 1
                                [last_updated] => 2022-07-11T08:39:59+02:00
                            )
                    )
                [whitelist_filters] => Array
                    (
                        [0] => Array
                            (
                                [enabled] => 1
                                [last_updated] => 2022-07-10T18:39:59+02:00
                            )

                    )
                [user_rules] => Array
            )
         */

        $filter_update = 0;
        if (isset($jdata['filters'])) {
            $filters = $jdata['filters'];
            if (is_array($filters)) {
                foreach ($filters as $filter) {
                    if ((bool) $filter['enabled'] == false) {
                        continue;
                    }
                    $ts = strtotime($filter['last_updated']);
                    if ($filter_update == 0 || $ts < $filter_update) {
                        $filter_update = $ts;
                    }
                }
            }
        }
        if (isset($jdata['whitelist_filters'])) {
            $filters = $jdata['whitelist_filters'];
            if (is_array($filters)) {
                foreach ($filters as $filter) {
                    if ((bool) $filter['enabled'] == false) {
                        continue;
                    }
                    $ts = strtotime($filter['last_updated']);
                    if ($filter_update == 0 || $ts < $filter_update) {
                        $filter_update = $ts;
                    }
                }
            }
        }
        $this->SendDebug(__FUNCTION__, 'filter_update=' . date('d.m.Y H:i:s', $filter_update), 0);
        $this->SetValue('filter_update', $filter_update);

        $this->SetValue('LastUpdate', time());

        $this->MaintainStatus(IS_ACTIVE);
        $this->SendDebug(__FUNCTION__, $this->PrintTimer('UpdateStatus'), 0);
    }

    private function do_HttpRequest($func, $params, $postdata, $mode, &$data)
    {
        $host = $this->ReadPropertyString('host');
        $use_https = $this->ReadPropertyBoolean('use_https');
        $user = $this->ReadPropertyString('user');
        $password = $this->ReadPropertyString('password');

        $url = ($use_https ? 'https://' : 'http://') . $host . '/control/' . $func;

        if ($params != '') {
            $n = 0;
            foreach ($params as $param => $value) {
                $url .= ($n++ ? '&' : '?') . $param . '=' . rawurlencode($value);
            }
        }

        $header = [
            'Accept: application/json; charset=utf-8',
        ];

        if ($mode == 'POST') {
            $header[] = 'Content-Type: application/json';
            $postdata = json_encode($postdata);
        }

        $this->SendDebug(__FUNCTION__, 'http-' . $mode . ': url=' . $url, 0);
        $this->SendDebug(__FUNCTION__, '    header=' . print_r($header, true), 0);
        if ($postdata != '') {
            $this->SendDebug(__FUNCTION__, '    postdata=' . $postdata, 0);
        }

        $time_start = microtime(true);

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        switch ($mode) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $mode);
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $mode);
                break;
        }
        curl_setopt($ch, CURLOPT_USERPWD, $user . ':' . $password);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        $cdata = curl_exec($ch);
        $cerrno = curl_errno($ch);
        $cerror = $cerrno ? curl_error($ch) : '';
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $redirect_url = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        $duration = round(microtime(true) - $time_start, 2);
        $this->SendDebug(__FUNCTION__, ' => errno=' . $cerrno . ', httpcode=' . $httpcode . ', duration=' . $duration . 's', 0);
        $this->SendDebug(__FUNCTION__, ' => cdata=' . $cdata, 0);

        $statuscode = 0;
        $err = '';
        $data = '';

        if ($cerrno) {
            $statuscode = self::$IS_SERVERERROR;
            $err = 'got curl-errno ' . $cerrno . ' (' . $cerror . ')';
        } elseif ($httpcode == 200 || $httpcode == 204) {
            $data = $cdata;
            if ($data != false) {
                $jdata = json_decode($data, true);
                if ($jdata == false) {
                    $statuscode = self::$IS_INVALIDDATA;
                    $err = 'malformed data';
                }
            }
        } elseif ($httpcode == 401) {
            $statuscode = self::$IS_UNAUTHORIZED;
            $err = 'got http-code ' . $httpcode . ' (unauthorized)';
        } elseif ($httpcode >= 500 && $httpcode <= 599) {
            $statuscode = self::$IS_SERVERERROR;
            $err = 'got http-code ' . $httpcode . ' (server error)';
        } else {
            $statuscode = self::$IS_HTTPERROR;
            $err = 'got http-code ' . $httpcode;
        }

        if ($statuscode) {
            $this->LogMessage('url=' . $url . ' => statuscode=' . $statuscode . ', err=' . $err, KL_WARNING);
            $this->SendDebug(__FUNCTION__, ' => statuscode=' . $statuscode . ', err=' . $err, 0);
        }

        return $statuscode;
    }
}
