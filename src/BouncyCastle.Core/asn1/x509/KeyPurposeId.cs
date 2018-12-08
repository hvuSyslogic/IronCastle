namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The KeyPurposeId object.
	/// <pre>
	///     KeyPurposeId ::= OBJECT IDENTIFIER
	/// 
	///     id-kp ::= OBJECT IDENTIFIER { iso(1) identified-organization(3)
	///          dod(6) internet(1) security(5) mechanisms(5) pkix(7) 3}
	/// 
	/// </pre>
	/// To create a new KeyPurposeId where none of the below suit, use
	/// <pre>
	///     ASN1ObjectIdentifier newKeyPurposeIdOID = new ASN1ObjectIdentifier("1.3.6.1...");
	/// 
	///     KeyPurposeId newKeyPurposeId = KeyPurposeId.getInstance(newKeyPurposeIdOID);
	/// </pre>
	/// </summary>
	public class KeyPurposeId : ASN1Object
	{
		private static readonly ASN1ObjectIdentifier id_kp = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.3");

		/// <summary>
		/// { 2 5 29 37 0 }
		/// </summary>
		public static readonly KeyPurposeId anyExtendedKeyUsage = new KeyPurposeId(Extension.extendedKeyUsage.branch("0"));

		/// <summary>
		/// { id-kp 1 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_serverAuth = new KeyPurposeId(id_kp.branch("1"));
		/// <summary>
		/// { id-kp 2 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_clientAuth = new KeyPurposeId(id_kp.branch("2"));
		/// <summary>
		/// { id-kp 3 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_codeSigning = new KeyPurposeId(id_kp.branch("3"));
		/// <summary>
		/// { id-kp 4 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_emailProtection = new KeyPurposeId(id_kp.branch("4"));
		/// <summary>
		/// Usage deprecated by RFC4945 - was { id-kp 5 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_ipsecEndSystem = new KeyPurposeId(id_kp.branch("5"));
		/// <summary>
		/// Usage deprecated by RFC4945 - was { id-kp 6 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_ipsecTunnel = new KeyPurposeId(id_kp.branch("6"));
		/// <summary>
		/// Usage deprecated by RFC4945 - was { idkp 7 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_ipsecUser = new KeyPurposeId(id_kp.branch("7"));
		/// <summary>
		/// { id-kp 8 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_timeStamping = new KeyPurposeId(id_kp.branch("8"));
		/// <summary>
		/// { id-kp 9 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_OCSPSigning = new KeyPurposeId(id_kp.branch("9"));
		/// <summary>
		/// { id-kp 10 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_dvcs = new KeyPurposeId(id_kp.branch("10"));
		/// <summary>
		/// { id-kp 11 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_sbgpCertAAServerAuth = new KeyPurposeId(id_kp.branch("11"));
		/// <summary>
		/// { id-kp 12 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_scvp_responder = new KeyPurposeId(id_kp.branch("12"));
		/// <summary>
		/// { id-kp 13 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_eapOverPPP = new KeyPurposeId(id_kp.branch("13"));
		/// <summary>
		/// { id-kp 14 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_eapOverLAN = new KeyPurposeId(id_kp.branch("14"));
		/// <summary>
		/// { id-kp 15 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_scvpServer = new KeyPurposeId(id_kp.branch("15"));
		/// <summary>
		/// { id-kp 16 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_scvpClient = new KeyPurposeId(id_kp.branch("16"));
		/// <summary>
		/// { id-kp 17 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_ipsecIKE = new KeyPurposeId(id_kp.branch("17"));
		/// <summary>
		/// { id-kp 18 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_capwapAC = new KeyPurposeId(id_kp.branch("18"));
		/// <summary>
		/// { id-kp 19 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_capwapWTP = new KeyPurposeId(id_kp.branch("19"));

		//
		// microsoft key purpose ids
		//
		/// <summary>
		/// { 1 3 6 1 4 1 311 20 2 2 }
		/// </summary>
		public static readonly KeyPurposeId id_kp_smartcardlogon = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"));


		/// 
		public static readonly KeyPurposeId id_kp_macAddress = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.1.1.1.22"));


		/// <summary>
		/// Microsoft Server Gated Crypto (msSGC) see http://www.alvestrand.no/objectid/1.3.6.1.4.1.311.10.3.3.html
		/// </summary>
		public static readonly KeyPurposeId id_kp_msSGC = new KeyPurposeId(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.10.3.3"));

		/// <summary>
		/// Netscape Server Gated Crypto (nsSGC) see http://www.alvestrand.no/objectid/2.16.840.1.113730.4.1.html
		/// </summary>
		public static readonly KeyPurposeId id_kp_nsSGC = new KeyPurposeId(new ASN1ObjectIdentifier("2.16.840.1.113730.4.1"));


		private ASN1ObjectIdentifier id;

		private KeyPurposeId(ASN1ObjectIdentifier id)
		{
			this.id = id;
		}

		/// <param name="id"> string representation of an OID. </param>
		/// @deprecated use getInstance and an OID or one of the constants above. 
		public KeyPurposeId(string id) : this(new ASN1ObjectIdentifier(id))
		{
		}

		public static KeyPurposeId getInstance(object o)
		{
			if (o is KeyPurposeId)
			{
				return (KeyPurposeId)o;
			}
			else if (o != null)
			{
				return new KeyPurposeId(ASN1ObjectIdentifier.getInstance(o));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier toOID()
		{
			return id;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return id;
		}

		public virtual string getId()
		{
			return id.getId();
		}

		public override string ToString()
		{
			return id.ToString();
		}
	}

}