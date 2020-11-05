<?php

declare(strict_types=1);

/*
 * This file is part of the "Password Field for Symphony CMS" Extension repository.
 *
 * Copyright 2020 Alannah Kearney
 *
 * For the full copyright and license information, please view the LICENCE
 * file that was distributed with this source code.
 */

require_once realpath(__DIR__.'/../vendor').'/autoload.php';

/**
 * This field is based on the "Member Password" field provided by the Members
 * extension. See, https://github.com/symphonycms/members for additional 
 * licence and credits information.
 *
 * Key changes are the removal of the Members extension specific functionality
 * and PHP7.4+ code syntax updates
 */
class fieldPassword extends Field implements ExportableField, ImportableField
{
    protected static $strengths = [];

    protected static $strengthMap = [
        'weak' => [0, 1],
        'good' => [2],
        'strong' => [3, 4],
    ];

    /*-------------------------------------------------------------------------
        Definition:
    -------------------------------------------------------------------------*/

    public function __construct()
    {
        parent::__construct();
        $this->_name = __('Password');
        $this->_required = true;

        $this->set('required', 'yes');
        $this->set('length', '6');
        $this->set('strength', 'good');

        self::$strengths = [
            ['weak', false, __('Weak')],
            ['good', false, __('Good')],
            ['strong', false, __('Strong')],
        ];
    }

    public function canFilter()
    {
        return true;
    }

    public function mustBeUnique()
    {
        return true;
    }

    /*-------------------------------------------------------------------------
        Setup:
    -------------------------------------------------------------------------*/

    public function createTable()
    {
        return Symphony::Database()->query(sprintf("
            CREATE TABLE IF NOT EXISTS `tbl_entries_data_%d` (
              `id` int(11) unsigned NOT NULL auto_increment,
              `entry_id` int(11) unsigned NOT NULL,
              `password` varchar(150) default NULL,
              `length` tinyint(2) NOT NULL,
              `strength` enum('weak', 'good', 'strong') NOT NULL,
              PRIMARY KEY  (`id`),
              KEY `entry_id` (`entry_id`),
              KEY `length` (`length`),
              KEY `password` (`password`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ", (int) $this->get('id')));
    }

    /*-------------------------------------------------------------------------
        Utilities:
    -------------------------------------------------------------------------*/

    /**
     * Given a string, this function will encode the password
     * using the PBKDF2 algorithm.
     */
    public function encodePassword(string $password): string
    {
        return Cryptography::hash($password);
    }

    protected static function checkPassword(string $password): ?string
    {
        $strength = 0;
        $patterns = [
            '/[a-z]/',
            '/[A-Z]/',
            '/[0-9]/',
            '/[¬!"£$%^&*()`{}\[\]:@~;\'#<>?,.\/\\-=_+\|]/',
        ];

        foreach ($patterns as $pattern) {
            if (true == preg_match($pattern, $password, $matches)) {
                ++$strength;
            }
        }

        foreach (self::$strengthMap as $key => $values) {
            if (false == in_array($strength, $values)) {
                continue;
            }

            return $key;
        }

        return null;
    }

    protected static function compareStrength(string $a, string $b): bool
    {
        if (array_sum(self::$strengthMap[$a]) >= array_sum(self::$strengthMap[$b])) {
            return true;
        }

        return false;
    }

    protected function rememberData(int $entryId): ?array
    {
        $fieldId = (int) $this->get('id');

        return Symphony::Database()->fetchRow(0, sprintf("
            SELECT f.password, f.strength, f.length
            FROM `tbl_entries_data_%d` AS `f`
            WHERE f.entry_id = '%d'
            LIMIT 1
        ", $fieldId, (int) $entryId));
    }

    public static function findCodeExpiry()
    {
        return extension_Members::findCodeExpiry('tbl_fields_memberpassword');
    }

    /*-------------------------------------------------------------------------
        Settings:
    -------------------------------------------------------------------------*/

    public function displaySettingsPanel(XMLElement &$wrapper, $errors = null)
    {
        parent::displaySettingsPanel($wrapper, $errors);
        $order = $this->get('sortorder');

        // Validator ----------------------------------------------------------

        $group = new XMLElement('div');
        $group->setAttribute('class', 'two columns');

        $label = Widget::Label(__('Minimum Length'));
        $label->setAttribute('class', 'column');
        $label->appendChild(Widget::Input(
            "fields[{$order}][length]", $this->get('length')
        ));

        $group->appendChild($label);

        // Strength -----------------------------------------------------------

        $values = self::$strengths;

        foreach ($values as &$value) {
            $value[1] = $value[0] == $this->get('strength');
        }

        $label = Widget::Label(__('Minimum Strength'));
        $label->setAttribute('class', 'column');
        $label->appendChild(Widget::Select(
            "fields[{$order}][strength]", $values
        ));

        $group->appendChild($label);
        $wrapper->appendChild($group);

        // Add checkboxes
        $div = new XMLElement('div', null, ['class' => 'two columns']);
        $this->appendRequiredCheckbox($div);
        $this->appendShowColumnCheckbox($div);
        $wrapper->appendChild($div);
    }

    public function commit()
    {
        if (!parent::commit()) {
            return false;
        }

        $id = $this->get('id');

        if (false === $id) {
            return false;
        }

        $fields = [
            'field_id' => $id,
            'length' => $this->get('length'),
            'strength' => $this->get('strength'),
        ];

        return FieldManager::saveSettings($id, $fields);
    }

    /*-------------------------------------------------------------------------
        Publish:
    -------------------------------------------------------------------------*/

    public function displayPublishPanel(XMLElement &$wrapper, $data = null, $error = null, $prefix = null, $postfix = null, $entryId = null)
    {
        $fieldId = (int) $this->get('id');
        $handle = $this->get('element_name');

        $group = new XMLElement('div');
        $group->setAttribute('class', 'two columns');

        // Password
        $password = $data['password'];
        $isPasswordSet = Symphony::Database()->fetchVar('id', 0, sprintf('
                SELECT f.id
                FROM `tbl_entries_data_%d` AS f
                WHERE f.entry_id = %d
                LIMIT 1
            ', $fieldId, (int) $entryId
        ));

        if (null !== $isPasswordSet) {
            $this->displayPublishPassword(
                $group, 'New Password', "{$prefix}[{$handle}][password]{$postfix}"
            );
            $this->displayPublishPassword(
                $group, 'Confirm New Password', "{$prefix}[{$handle}][confirm]{$postfix}"
            );

            $group->appendChild(Widget::Input(
                "fields{$prefix}[{$handle}][optional]{$postfix}", 'yes', 'hidden'
            ));

            $help = new XMLElement('p');
            $help->setAttribute('class', 'help');
            $help->setValue(__('Leave new password field blank to keep the current password'));
        } else {
            $this->displayPublishPassword(
                $group, 'Password', "{$prefix}[{$handle}][password]{$postfix}"
            );
            $this->displayPublishPassword(
                $group, 'Confirm Password', "{$prefix}[{$handle}][confirm]{$postfix}"
            );
        }

        // Error?
        if (null != $error) {
            $group = Widget::Error($group, $error);
            $wrapper->appendChild($group);
        } else {
            $wrapper->appendChild($group);
            if ($help instanceof XMLElement) {
                $wrapper->appendChild($help);
            }
        }
    }

    public function displayPublishPassword(XMLElement $wrapper, string $title, string $name)
    {
        $required = (bool) ('yes' == $this->get('required'));

        $label = Widget::Label(__($title));
        $label->setAttribute('class', 'column');
        if (false == $required) {
            $label->appendChild(new XMLElement('i', __('Optional')));
        }

        $input = Widget::Input("fields{$name}", null, 'password', ['autocomplete' => 'off']);

        $label->appendChild($input);
        $wrapper->appendChild($label);
    }

    /*-------------------------------------------------------------------------
        Input:
    -------------------------------------------------------------------------*/

    public function checkPostFieldData($data, &$message, $entryId = null)
    {
        $message = null;
        $required = (bool) ('yes' == $this->get('required'));

        $password = trim($data['password']);
        $confirm = trim($data['confirm']);

        // If the field is required, we should have both a $username and $password.
        if (true == $required && false == isset($data['optional']) && (true == empty($password))) {
            $message = __('%s is a required field.', [$this->get('label')]);

            return self::__MISSING_FIELDS__;
        }

        // Check password
        if (false == empty($password) || false == empty($confirm)) {
            if ($confirm !== $password) {
                $message = __('%s confirmation does not match.', [$this->get('label')]);

                return self::__INVALID_FIELDS__;
            }

            if (strlen($password) < (int) $this->get('length')) {
                $message = __('%s is too short. It must be at least %d characters.', [$this->get('label'), $this->get('length')]);

                return self::__INVALID_FIELDS__;
            }

            if (false == self::compareStrength(self::checkPassword($password), $this->get('strength'))) {
                $message = __('%s is not strong enough.', [$this->get('label')]);

                return self::__INVALID_FIELDS__;
            }
        } elseif (true == $required && false == isset($data['optional'])) {
            $message = __('%s cannot be blank.', [$this->get('label')]);

            return self::__MISSING_FIELDS__;
        }

        return self::__OK__;
    }

    public function processRawFieldData($data, &$status, &$message = null, $simulate = false, $entryId = null)
    {
        $status = self::__OK__;
        $required = (bool) ('yes' == $this->get('required'));

        if (true == empty($data)) {
            return [];
        }

        $password = trim($data['password']);

        // We only want to run the processing if the password has been altered
        // or if the entry hasn't been created yet. If someone attempts to change
        // their username, but not their password, this will be caught by checkPostFieldData
        if (false == empty($password) || null == $entryId) {
            return [
                'password' => $this->encodePassword($password),
                'strength' => self::checkPassword($password),
                'length' => strlen($password),
            ];
        }

        return $this->rememberData((int) $entryId);
    }

    /*-------------------------------------------------------------------------
        Output:
    -------------------------------------------------------------------------*/

    public function appendFormattedElement(XMLElement &$wrapper, $data, $encode = false, $mode = null, $entryId = null)
    {
        $pw = new XMLElement($this->get('element_name'));

        // Output the hash of the password.
        if (true == isset($data['password']) && !empty($data['password'])) {
            $pw->setValue($data['password']);
        }

        $wrapper->appendChild($pw);
    }

    public function prepareTableValue($data, XMLElement $link = null, $entryId = null)
    {
        if (true == empty($data)) {
            return __('None');
        }

        return parent::prepareTableValue([
            'value' => __(ucwords($data['strength'])).' ('.$data['length'].')',
        ], $link, $entryId);
    }

    /*-------------------------------------------------------------------------
        Import:
    -------------------------------------------------------------------------*/

    public function getImportModes()
    {
        return [
            'getPostdata' => ImportableField::ARRAY_VALUE,
        ];
    }

    public function prepareImportValue($data, $mode, $entryId = null)
    {
        $message = null;
        $status = null;

        if ($mode === (object) ($this->getImportModes())->getPostdata) {
            return $this->processRawFieldData($data, $status, $message, true, $entryId);
        }

        return null;
    }

    /*-------------------------------------------------------------------------
        Export:
    -------------------------------------------------------------------------*/

    public function getExportModes()
    {
        return [
            ExportableField::POSTDATA,
        ];
    }

    public function prepareExportValue($data, $mode, $entryId = null)
    {
        return null;
    }

    /*-------------------------------------------------------------------------
        Filtering:
    -------------------------------------------------------------------------*/

    public function buildDSRetrievalSQL($data, &$joins, &$where, $andOperation = false)
    {
        $fieldId = (int) $this->get('id');

        if ($andOperation) {
            foreach ($data as $key => $value) {
                ++$this->_key;
                $value = $this->encodePassword($value);
                $value = Symphony::Database()->cleanValue($value);
                $joins .= " LEFT JOIN `tbl_entries_data_{$fieldId}` AS `t{$fieldId}{$key}` ON (`e`.`id` = `t{$fieldId}{$key}`.entry_id) ";
                $where .= " AND `t{$fieldId}{$key}`.password = '{$value}' ";
            }
        } else {
            if (true == is_array($data) && true == isset($data['password'])) {
                $data = [$data['password']];
            } elseif (false == is_array($data)) {
                $data = [$data];
            }

            foreach ($data as &$value) {
                $value = $this->encodePassword($value);
            }

            $data = array_map([Symphony::Database(), 'cleanValue'], $data);
            $data = implode("', '", $data);
            $joins .= " LEFT JOIN `tbl_entries_data_{$fieldId}` AS `t{$fieldId}` ON (`e`.`id` = `t{$fieldId}`.entry_id) ";
            $where .= " AND `t{$fieldId}`.password IN ('{$data}') ";
        }

        return true;
    }

    /*-------------------------------------------------------------------------
        Events:
    -------------------------------------------------------------------------*/

    public function getExampleFormMarkup()
    {
        $fieldset = new XMLElement('fieldset');

        $label = Widget::Label($this->get('label'));
        $label->appendChild(Widget::Input('fields['.$this->get('element_name').'][password]', null, 'password'));

        $fieldset->appendChild($label);

        $label = Widget::Label($this->get('label').' '.__('Confirm'));
        $label->appendChild(Widget::Input('fields['.$this->get('element_name').'][confirm]', null, 'password'));

        $fieldset->appendChild($label);

        return $fieldset;
    }
}
