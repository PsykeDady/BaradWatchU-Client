//! CP5 building block: parse supplied pwquality settings, not PAM enforcement.
//!
//! The caller must establish the complete source set and order: sorted drop-ins,
//! then the main file, then PAM arguments. Missing keys remain unknown. This
//! module does not access the filesystem, select PAM stacks, or produce a verdict.

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QualitySettings {
    pub min_length: Option<i32>,
    pub min_classes: Option<i32>,
    pub upper_credit: Option<i32>,
    pub lower_credit: Option<i32>,
    pub digit_credit: Option<i32>,
    pub other_credit: Option<i32>,
    pub enforcing: Option<bool>,
    pub local_users_only: Option<bool>,
    pub enforce_for_root: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidSyntax,
    InvalidValue,
    CustomConfiguration,
    UnsupportedSetting,
}

impl QualitySettings {
    fn set(&mut self, key: &str, value: &str) -> Result<(), ParseError> {
        let key = key.to_ascii_lowercase();
        let key = key.as_str();
        if key == "conf" {
            return Err(ParseError::CustomConfiguration);
        }
        // Recognized additional checks/prompt settings cannot weaken the modeled
        // length/classes; still validate numeric syntax rather than ignoring errors.
        if matches!(
            key,
            "retry"
                | "difok"
                | "maxrepeat"
                | "maxsequence"
                | "maxclassrepeat"
                | "gecoscheck"
                | "dictcheck"
                | "usercheck"
                | "usersubstr"
        ) {
            let n: i32 = value.parse().map_err(|_| ParseError::InvalidValue)?;
            return if (0..i32::MAX).contains(&n) {
                Ok(())
            } else {
                Err(ParseError::InvalidValue)
            };
        }
        if key == "local_users_only" || key == "enforce_for_root" {
            if !value.is_empty() {
                return Err(ParseError::InvalidValue);
            }
            if key == "local_users_only" {
                self.local_users_only = Some(true);
            } else {
                self.enforce_for_root = Some(true);
            }
            return Ok(());
        }
        if !matches!(
            key,
            "minlen" | "minclass" | "ucredit" | "lcredit" | "dcredit" | "ocredit" | "enforcing"
        ) {
            return Err(ParseError::UnsupportedSetting);
        }
        let number: i32 = value.parse().map_err(|_| ParseError::InvalidValue)?;
        // libpwquality's strtol adapter rejects both signed integer endpoints.
        if number == i32::MIN || number == i32::MAX {
            return Err(ParseError::InvalidValue);
        }
        match key {
            // libpwquality clamps nonnegative minlen below its base minimum.
            "minlen" if number >= 0 => self.min_length = Some(number.max(6)),
            "minclass" if (0..=4).contains(&number) => self.min_classes = Some(number),
            "ucredit" => self.upper_credit = Some(number),
            "lcredit" => self.lower_credit = Some(number),
            "dcredit" => self.digit_credit = Some(number),
            "ocredit" => self.other_credit = Some(number),
            "enforcing" => self.enforcing = Some(number != 0),
            _ => return Err(ParseError::InvalidValue),
        }
        Ok(())
    }

    /// Apply one already selected configuration file; never retains other values.
    pub fn apply_file(&mut self, text: &str) -> Result<(), ParseError> {
        for line in text.lines() {
            // Match the upstream bounded line reader conservatively. Otherwise
            // a long line could be parsed here but rejected by the real library.
            if line.len() >= 1023 {
                return Err(ParseError::InvalidSyntax);
            }
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some((k, v)) => (k.trim(), v.trim()),
                None if line.eq_ignore_ascii_case("local_users_only")
                    || line.eq_ignore_ascii_case("enforce_for_root") =>
                {
                    (line, "")
                }
                None => return Err(ParseError::InvalidSyntax),
            };
            if key.is_empty() {
                return Err(ParseError::InvalidSyntax);
            }
            self.set(key, value)?;
        }
        Ok(())
    }

    /// Apply arguments from one selected pam_pwquality invocation.
    pub fn apply_arguments<'a>(
        &mut self,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), ParseError> {
        for arg in args {
            let (key, value) = arg.split_once('=').unwrap_or((arg, ""));
            self.set(key, value)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_files_and_module_arguments_override_earlier_values() {
        let mut settings = QualitySettings::default();
        settings.apply_file("minlen = 20\nucredit = -1\n").unwrap();
        settings.apply_file("minlen = 16\nminclass = 4\n").unwrap();
        settings
            .apply_arguments(["minlen=14", "ucredit=0"])
            .unwrap();
        assert_eq!(settings.min_length, Some(14));
        assert_eq!(settings.upper_credit, Some(0));
        assert_eq!(settings.min_classes, Some(4));
        assert_eq!(settings.lower_credit, None);
    }

    #[test]
    fn minclass_does_not_imply_individual_requirements() {
        let mut settings = QualitySettings::default();
        settings.apply_file("minclass = 4").unwrap();
        assert_eq!(settings.upper_credit, None);
        assert_eq!(settings.lower_credit, None);
        assert_eq!(settings.digit_credit, None);
        assert_eq!(settings.other_credit, None);
    }

    #[test]
    fn malformed_values_and_custom_configuration_are_rejected() {
        let mut settings = QualitySettings::default();
        assert_eq!(
            settings.apply_file("minclass = 5"),
            Err(ParseError::InvalidValue)
        );
        assert_eq!(
            settings.apply_arguments(["conf=/other"]),
            Err(ParseError::CustomConfiguration)
        );
        assert_eq!(
            settings.apply_file("minlen"),
            Err(ParseError::InvalidSyntax)
        );
        assert_eq!(
            settings.apply_arguments(["unknown=1"]),
            Err(ParseError::UnsupportedSetting)
        );
    }

    #[test]
    fn flags_and_disabled_enforcement_remain_distinct() {
        let mut settings = QualitySettings::default();
        settings
            .apply_file("enforcing = 0\nlocal_users_only\n")
            .unwrap();
        settings.apply_arguments(["enforce_for_root"]).unwrap();
        assert_eq!(settings.enforcing, Some(false));
        assert_eq!(settings.local_users_only, Some(true));
        assert_eq!(settings.enforce_for_root, Some(true));
    }

    #[test]
    fn setting_names_are_case_insensitive() {
        let mut settings = QualitySettings::default();
        settings.apply_file("MINLEN = 14").unwrap();
        settings.apply_arguments(["MINLEN=9"]).unwrap();
        assert_eq!(settings.min_length, Some(9));
        settings.apply_arguments(["minlen=0"]).unwrap();
        assert_eq!(settings.min_length, Some(6));
    }
}
