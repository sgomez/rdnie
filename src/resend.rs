// Derived from JMulticard (https://github.com/ctt-gob-es/jmulticard, commit 4ec9494):
// - es.gob.jmulticard.connection.AbstractApduConnectionIso7816 (Tomás García-Merás)
// rdnie takes the EUPL 1.1+ branch of the dual licence below.
//
// Controlador Java de la Secretaria de Estado de Administraciones Publicas
// para el DNI electronico.
//
// El Controlador Java para el DNI electronico es un proveedor de seguridad de JCA/JCE
// que permite el acceso y uso del DNI electronico en aplicaciones Java de terceros
// para la realizacion de procesos de autenticacion, firma electronica y validacion
// de firma. Para ello, se implementan las funcionalidades KeyStore y Signature para
// el acceso a los certificados y claves del DNI electronico, asi como la realizacion
// de operaciones criptograficas de firma con el DNI electronico. El Controlador ha
// sido disenado para su funcionamiento independiente del sistema operativo final.
//
// Copyright (C) 2012 Direccion General de Modernizacion Administrativa, Procedimientos
// e Impulso de la Administracion Electronica
//
// Este programa es software libre y utiliza un licenciamiento dual (LGPL 2.1+
// o EUPL 1.1+), lo cual significa que los usuarios podran elegir bajo cual de las
// licencias desean utilizar el codigo fuente. Su eleccion debera reflejarse
// en las aplicaciones que integren o distribuyan el Controlador, ya que determinara
// su compatibilidad con otros componentes.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// Lesser GNU General Public License publicada por la Free Software Foundation,
// tanto en la version 2.1 de la Licencia, o en una version posterior.
//
// El Controlador puede ser redistribuido y/o modificado bajo los terminos de la
// European Union Public License publicada por la Comision Europea,
// tanto en la version 1.1 de la Licencia, o en una version posterior.
//
// Deberia recibir una copia de la GNU Lesser General Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://www.gnu.org/licenses/>.
//
// Deberia recibir una copia de la European Union Public License, si aplica, junto
// con este programa. Si no, consultelo en <http://joinup.ec.europa.eu/software/page/eupl>.
//
// Este programa es distribuido con la esperanza de que sea util, pero
// SIN NINGUNA GARANTIA; incluso sin la garantia implicita de comercializacion
// o idoneidad para un proposito particular.

//! The bounded `6Cxx` resend shared by the transport and the secure channel.

use zeroize::Zeroize;

use crate::{Command, Error, StatusWord};

const WRONG_LENGTH: u8 = 0x6C;
const MAX_RESENDS: usize = 2;

/// Holds the latest resent copy of a command and wipes it on drop.
#[derive(Default)]
pub(crate) struct Resends {
    copy: Option<Command>,
    consecutive: usize,
}

impl Resends {
    /// The command to send now: the latest copy, or `command` if none was made.
    pub(crate) fn current<'a>(&'a self, command: &'a Command) -> &'a Command {
        self.copy.as_ref().unwrap_or(command)
    }

    /// Whether `status` is a `6Cxx` asking for another Le.
    pub(crate) fn is_wrong_length(status: StatusWord) -> bool {
        status.0.to_be_bytes()[0] == WRONG_LENGTH
    }

    /// Replaces the current command by a copy with the Le a `6Cxx` asks for.
    ///
    /// # Errors
    ///
    /// [`Error::Status`] with `status` once 2 resends in a row were made.
    pub(crate) fn resend_with_le(
        &mut self,
        command: &Command,
        status: StatusWord,
    ) -> Result<(), Error> {
        if self.consecutive == MAX_RESENDS {
            return Err(Error::Status(status));
        }
        self.consecutive += 1;
        let next = Command {
            le: Some(short_le(status.0.to_be_bytes()[1])),
            ..self.current(command).clone()
        };
        self.replace(next);
        Ok(())
    }

    /// Replaces the current command by an unrelated one and ends the run of resends.
    pub(crate) fn replace_with(&mut self, next: Command) {
        self.consecutive = 0;
        self.replace(next);
    }

    fn replace(&mut self, next: Command) {
        if let Some(mut old) = self.copy.replace(next) {
            old.data.zeroize();
        }
    }
}

impl Drop for Resends {
    fn drop(&mut self) {
        if let Some(copy) = &mut self.copy {
            copy.data.zeroize();
        }
    }
}

pub(crate) fn short_le(le: u8) -> u16 {
    match le {
        0 => 256,
        le => le.into(),
    }
}
