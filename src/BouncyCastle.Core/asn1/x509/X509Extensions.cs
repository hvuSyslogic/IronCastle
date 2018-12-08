using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// @deprecated use Extensions 
	public class X509Extensions : ASN1Object
	{
		/// <summary>
		/// Subject Directory Attributes </summary>
		/// @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier SubjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9");

		/// <summary>
		/// Subject Key Identifier </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier SubjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14");

		/// <summary>
		/// Key Usage </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier KeyUsage = new ASN1ObjectIdentifier("2.5.29.15");

		/// <summary>
		/// Private Key Usage Period </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier PrivateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16");

		/// <summary>
		/// Subject Alternative Name </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier SubjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17");

		/// <summary>
		/// Issuer Alternative Name </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier IssuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18");

		/// <summary>
		/// Basic Constraints </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier BasicConstraints = new ASN1ObjectIdentifier("2.5.29.19");

		/// <summary>
		/// CRL Number </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier CRLNumber = new ASN1ObjectIdentifier("2.5.29.20");

		/// <summary>
		/// Reason code </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier ReasonCode = new ASN1ObjectIdentifier("2.5.29.21");

		/// <summary>
		/// Hold Instruction Code </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier InstructionCode = new ASN1ObjectIdentifier("2.5.29.23");

		/// <summary>
		/// Invalidity Date </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier InvalidityDate = new ASN1ObjectIdentifier("2.5.29.24");

		/// <summary>
		/// Delta CRL indicator </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier DeltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27");

		/// <summary>
		/// Issuing Distribution Point </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier IssuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28");

		/// <summary>
		/// Certificate Issuer </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier CertificateIssuer = new ASN1ObjectIdentifier("2.5.29.29");

		/// <summary>
		/// Name Constraints </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier NameConstraints = new ASN1ObjectIdentifier("2.5.29.30");

		/// <summary>
		/// CRL Distribution Points </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier CRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");

		/// <summary>
		/// Certificate Policies </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier CertificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");

		/// <summary>
		/// Policy Mappings </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier PolicyMappings = new ASN1ObjectIdentifier("2.5.29.33");

		/// <summary>
		/// Authority Key Identifier </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier AuthorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35");

		/// <summary>
		/// Policy Constraints </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier PolicyConstraints = new ASN1ObjectIdentifier("2.5.29.36");

		/// <summary>
		/// Extended Key Usage </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier ExtendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37");

		/// <summary>
		/// Freshest CRL </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier FreshestCRL = new ASN1ObjectIdentifier("2.5.29.46");

		/// <summary>
		/// Inhibit Any Policy </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier InhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54");

		/// <summary>
		/// Authority Info Access </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier AuthorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1");

		/// <summary>
		/// Subject Info Access </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier SubjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11");

		/// <summary>
		/// Logo Type </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier LogoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12");

		/// <summary>
		/// BiometricInfo </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier BiometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2");

		/// <summary>
		/// QCStatements </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier QCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");

		/// <summary>
		/// Audit identity extension in attribute certificates. </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier AuditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4");

		/// <summary>
		/// NoRevAvail extension in attribute certificates. </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier NoRevAvail = new ASN1ObjectIdentifier("2.5.29.56");

		/// <summary>
		/// TargetInformation extension in attribute certificates. </summary>
		///  @deprecated use X509Extension value. 
		public static readonly ASN1ObjectIdentifier TargetInformation = new ASN1ObjectIdentifier("2.5.29.55");

		private Hashtable extensions = new Hashtable();
		private Vector ordering = new Vector();

		public static X509Extensions getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static X509Extensions getInstance(object obj)
		{
			if (obj == null || obj is X509Extensions)
			{
				return (X509Extensions)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new X509Extensions((ASN1Sequence)obj);
			}

			if (obj is Extensions)
			{
				return new X509Extensions((ASN1Sequence)((Extensions)obj).toASN1Primitive());
			}

			if (obj is ASN1TaggedObject)
			{
				return getInstance(((ASN1TaggedObject)obj).getObject());
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// 
		/// the extensions are a list of constructed sequences, either with (OID, OctetString) or (OID, Boolean, OctetString)
		/// </summary>
		public X509Extensions(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1Sequence s = ASN1Sequence.getInstance(e.nextElement());

				if (s.size() == 3)
				{
					extensions.put(s.getObjectAt(0), new X509Extension(ASN1Boolean.getInstance(s.getObjectAt(1)), ASN1OctetString.getInstance(s.getObjectAt(2))));
				}
				else if (s.size() == 2)
				{
					extensions.put(s.getObjectAt(0), new X509Extension(false, ASN1OctetString.getInstance(s.getObjectAt(1))));
				}
				else
				{
					throw new IllegalArgumentException("Bad sequence size: " + s.size());
				}

				ordering.addElement(s.getObjectAt(0));
			}
		}

		/// <summary>
		/// constructor from a table of extensions.
		/// <para>
		/// it's is assumed the table contains OID/String pairs.
		/// </para>
		/// </summary>
		public X509Extensions(Hashtable extensions) : this(null, extensions)
		{
		}

		/// <summary>
		/// Constructor from a table of extensions with ordering.
		/// <para>
		/// It's is assumed the table contains OID/String pairs.
		/// </para>
		/// </summary>
		/// @deprecated use Extensions 
		public X509Extensions(Vector ordering, Hashtable extensions)
		{
			Enumeration e;

			if (ordering == null)
			{
				e = extensions.keys();
			}
			else
			{
				e = ordering.elements();
			}

			while (e.hasMoreElements())
			{
				this.ordering.addElement(ASN1ObjectIdentifier.getInstance(e.nextElement()));
			}

			e = this.ordering.elements();

			while (e.hasMoreElements())
			{
				ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(e.nextElement());
				X509Extension ext = (X509Extension)extensions.get(oid);

				this.extensions.put(oid, ext);
			}
		}

		/// <summary>
		/// Constructor from two vectors
		/// </summary>
		/// <param name="objectIDs"> a vector of the object identifiers. </param>
		/// <param name="values"> a vector of the extension values. </param>
		/// @deprecated use Extensions 
		public X509Extensions(Vector objectIDs, Vector values)
		{
			Enumeration e = objectIDs.elements();

			while (e.hasMoreElements())
			{
				this.ordering.addElement(e.nextElement());
			}

			int count = 0;

			e = this.ordering.elements();

			while (e.hasMoreElements())
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
				X509Extension ext = (X509Extension)values.elementAt(count);

				this.extensions.put(oid, ext);
				count++;
			}
		}

		/// <summary>
		/// return an Enumeration of the extension field's object ids.
		/// </summary>
		public virtual Enumeration oids()
		{
			return ordering.elements();
		}

		/// <summary>
		/// return the extension represented by the object identifier
		/// passed in.
		/// </summary>
		/// <returns> the extension if it's present, null otherwise. </returns>
		public virtual X509Extension getExtension(ASN1ObjectIdentifier oid)
		{
			return (X509Extension)extensions.get(oid);
		}

		/// <summary>
		/// <pre>
		///     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
		/// 
		///     Extension         ::=   SEQUENCE {
		///        extnId            EXTENSION.&amp;id ({ExtensionSet}),
		///        critical          BOOLEAN DEFAULT FALSE,
		///        extnValue         OCTET STRING }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			Enumeration e = ordering.elements();

			while (e.hasMoreElements())
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
				X509Extension ext = (X509Extension)extensions.get(oid);
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(oid);

				if (ext.isCritical())
				{
					v.add(ASN1Boolean.TRUE);
				}

				v.add(ext.getValue());

				vec.add(new DERSequence(v));
			}

			return new DERSequence(vec);
		}

		public virtual bool equivalent(X509Extensions other)
		{
			if (extensions.size() != other.extensions.size())
			{
				return false;
			}

			Enumeration e1 = extensions.keys();

			while (e1.hasMoreElements())
			{
				object key = e1.nextElement();

				if (!extensions.get(key).Equals(other.extensions.get(key)))
				{
					return false;
				}
			}

			return true;
		}

		public virtual ASN1ObjectIdentifier[] getExtensionOIDs()
		{
			return toOidArray(ordering);
		}

		public virtual ASN1ObjectIdentifier[] getNonCriticalExtensionOIDs()
		{
			return getExtensionOIDs(false);
		}

		public virtual ASN1ObjectIdentifier[] getCriticalExtensionOIDs()
		{
			return getExtensionOIDs(true);
		}

		private ASN1ObjectIdentifier[] getExtensionOIDs(bool isCritical)
		{
			Vector oidVec = new Vector();

			for (int i = 0; i != ordering.size(); i++)
			{
				object oid = ordering.elementAt(i);

				if (((X509Extension)extensions.get(oid)).isCritical() == isCritical)
				{
					oidVec.addElement(oid);
				}
			}

			return toOidArray(oidVec);
		}

		private ASN1ObjectIdentifier[] toOidArray(Vector oidVec)
		{
			ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[oidVec.size()];

			for (int i = 0; i != oids.Length; i++)
			{
				oids[i] = (ASN1ObjectIdentifier)oidVec.elementAt(i);
			}
			return oids;
		}
	}

}