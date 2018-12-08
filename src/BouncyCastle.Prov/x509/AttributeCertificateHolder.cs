using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using Holder = org.bouncycastle.asn1.x509.Holder;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using ObjectDigestInfo = org.bouncycastle.asn1.x509.ObjectDigestInfo;
	using PrincipalUtil = org.bouncycastle.jce.PrincipalUtil;
	using X509Principal = org.bouncycastle.jce.X509Principal;
	using Arrays = org.bouncycastle.util.Arrays;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// The Holder object.
	/// 
	/// <pre>
	///          Holder ::= SEQUENCE {
	///                baseCertificateID   [0] IssuerSerial OPTIONAL,
	///                         -- the issuer and serial number of
	///                         -- the holder's Public Key Certificate
	///                entityName          [1] GeneralNames OPTIONAL,
	///                         -- the name of the claimant or role
	///                objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
	///                         -- used to directly authenticate the holder,
	///                         -- for example, an executable
	///          }
	/// </pre> </summary>
	/// @deprecated use org.bouncycastle.cert.AttributeCertificateHolder 
	public class AttributeCertificateHolder : CertSelector, Selector
	{
		internal readonly Holder holder;

		public AttributeCertificateHolder(ASN1Sequence seq)
		{
			holder = Holder.getInstance(seq);
		}

		public AttributeCertificateHolder(X509Principal issuerName, BigInteger serialNumber)
		{
			holder = new Holder(new IssuerSerial(GeneralNames.getInstance(new DERSequence(new GeneralName(issuerName))), new ASN1Integer(serialNumber)));
		}

		public AttributeCertificateHolder(X500Principal issuerName, BigInteger serialNumber) : this(X509Util.convertPrincipal(issuerName), serialNumber)
		{
		}

		public AttributeCertificateHolder(X509Certificate cert)
		{
			X509Principal name;

			try
			{
				name = PrincipalUtil.getIssuerX509Principal(cert);
			}
			catch (Exception e)
			{
				throw new CertificateParsingException(e.Message);
			}

			holder = new Holder(new IssuerSerial(generateGeneralNames(name), new ASN1Integer(cert.getSerialNumber())));
		}

		public AttributeCertificateHolder(X509Principal principal)
		{
			holder = new Holder(generateGeneralNames(principal));
		}

		public AttributeCertificateHolder(X500Principal principal) : this(X509Util.convertPrincipal(principal))
		{
		}

		/// <summary>
		/// Constructs a holder for v2 attribute certificates with a hash value for
		/// some type of object.
		/// <para>
		/// <code>digestedObjectType</code> can be one of the following:
		/// <ul>
		/// <li>0 - publicKey - A hash of the public key of the holder must be
		/// passed.
		/// <li>1 - publicKeyCert - A hash of the public key certificate of the
		/// holder must be passed.
		/// <li>2 - otherObjectDigest - A hash of some other object type must be
		/// passed. <code>otherObjectTypeID</code> must not be empty.
		/// </ul>
		/// </para>
		/// <para>
		/// This cannot be used if a v1 attribute certificate is used.
		/// 
		/// </para>
		/// </summary>
		/// <param name="digestedObjectType"> The digest object type. </param>
		/// <param name="digestAlgorithm"> The algorithm identifier for the hash. </param>
		/// <param name="otherObjectTypeID"> The object type ID if
		///            <code>digestedObjectType</code> is
		///            <code>otherObjectDigest</code>. </param>
		/// <param name="objectDigest"> The hash value. </param>
		public AttributeCertificateHolder(int digestedObjectType, string digestAlgorithm, string otherObjectTypeID, byte[] objectDigest)
		{
			holder = new Holder(new ObjectDigestInfo(digestedObjectType, new ASN1ObjectIdentifier(otherObjectTypeID), new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm)), Arrays.clone(objectDigest)));
		}

		/// <summary>
		/// Returns the digest object type if an object digest info is used.
		/// <para>
		/// <ul>
		/// <li>0 - publicKey - A hash of the public key of the holder must be
		/// passed.
		/// <li>1 - publicKeyCert - A hash of the public key certificate of the
		/// holder must be passed.
		/// <li>2 - otherObjectDigest - A hash of some other object type must be
		/// passed. <code>otherObjectTypeID</code> must not be empty.
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <returns> The digest object type or -1 if no object digest info is set. </returns>
		public virtual int getDigestedObjectType()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				return holder.getObjectDigestInfo().getDigestedObjectType().getValue().intValue();
			}
			return -1;
		}

		/// <summary>
		/// Returns the other object type ID if an object digest info is used.
		/// </summary>
		/// <returns> The other object type ID or <code>null</code> if no object
		///         digest info is set. </returns>
		public virtual string getDigestAlgorithm()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				return holder.getObjectDigestInfo().getDigestAlgorithm().getAlgorithm().getId();
			}
			return null;
		}

		/// <summary>
		/// Returns the hash if an object digest info is used.
		/// </summary>
		/// <returns> The hash or <code>null</code> if no object digest info is set. </returns>
		public virtual byte[] getObjectDigest()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				return holder.getObjectDigestInfo().getObjectDigest().getBytes();
			}
			return null;
		}

		/// <summary>
		/// Returns the digest algorithm ID if an object digest info is used.
		/// </summary>
		/// <returns> The digest algorithm ID or <code>null</code> if no object
		///         digest info is set. </returns>
		public virtual string getOtherObjectTypeID()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				holder.getObjectDigestInfo().getOtherObjectTypeID().getId();
			}
			return null;
		}

		private GeneralNames generateGeneralNames(X509Principal principal)
		{
			return GeneralNames.getInstance(new DERSequence(new GeneralName(principal)));
		}

		private bool matchesDN(X509Principal subject, GeneralNames targets)
		{
			GeneralName[] names = targets.getNames();

			for (int i = 0; i != names.Length; i++)
			{
				GeneralName gn = names[i];

				if (gn.getTagNo() == GeneralName.directoryName)
				{
					try
					{
						if ((new X509Principal(((ASN1Encodable)gn.getName()).toASN1Primitive().getEncoded())).Equals(subject))
						{
							return true;
						}
					}
					catch (IOException)
					{
					}
				}
			}

			return false;
		}

		private object[] getNames(GeneralName[] names)
		{
			List l = new ArrayList(names.Length);

			for (int i = 0; i != names.Length; i++)
			{
				if (names[i].getTagNo() == GeneralName.directoryName)
				{
					try
					{
						l.add(new X500Principal(((ASN1Encodable)names[i].getName()).toASN1Primitive().getEncoded()));
					}
					catch (IOException)
					{
						throw new RuntimeException("badly formed Name object");
					}
				}
			}

			return l.toArray(new object[l.size()]);
		}

		private Principal[] getPrincipals(GeneralNames names)
		{
			object[] p = this.getNames(names.getNames());
			List l = new ArrayList();

			for (int i = 0; i != p.Length; i++)
			{
				if (p[i] is Principal)
				{
					l.add(p[i]);
				}
			}

			return (Principal[])l.toArray(new Principal[l.size()]);
		}

		/// <summary>
		/// Return any principal objects inside the attribute certificate holder
		/// entity names field.
		/// </summary>
		/// <returns> an array of Principal objects (usually X500Principal), null if no
		///         entity names field is set. </returns>
		public virtual Principal[] getEntityNames()
		{
			if (holder.getEntityName() != null)
			{
				return getPrincipals(holder.getEntityName());
			}

			return null;
		}

		/// <summary>
		/// Return the principals associated with the issuer attached to this holder
		/// </summary>
		/// <returns> an array of principals, null if no BaseCertificateID is set. </returns>
		public virtual Principal[] getIssuer()
		{
			if (holder.getBaseCertificateID() != null)
			{
				return getPrincipals(holder.getBaseCertificateID().getIssuer());
			}

			return null;
		}

		/// <summary>
		/// Return the serial number associated with the issuer attached to this
		/// holder.
		/// </summary>
		/// <returns> the certificate serial number, null if no BaseCertificateID is
		///         set. </returns>
		public virtual BigInteger getSerialNumber()
		{
			if (holder.getBaseCertificateID() != null)
			{
				return holder.getBaseCertificateID().getSerial().getValue();
			}

			return null;
		}

		public virtual object clone()
		{
			return new AttributeCertificateHolder((ASN1Sequence)holder.toASN1Primitive());
		}

		public virtual bool match(Certificate cert)
		{
			if (!(cert is X509Certificate))
			{
				return false;
			}

			X509Certificate x509Cert = (X509Certificate)cert;

			try
			{
				if (holder.getBaseCertificateID() != null)
				{
					return holder.getBaseCertificateID().getSerial().getValue().Equals(x509Cert.getSerialNumber()) && matchesDN(PrincipalUtil.getIssuerX509Principal(x509Cert), holder.getBaseCertificateID().getIssuer());
				}

				if (holder.getEntityName() != null)
				{
					if (matchesDN(PrincipalUtil.getSubjectX509Principal(x509Cert), holder.getEntityName()))
					{
						return true;
					}
				}
				if (holder.getObjectDigestInfo() != null)
				{
					MessageDigest md = null;
					try
					{
						md = MessageDigest.getInstance(getDigestAlgorithm(), "BC");

					}
					catch (Exception)
					{
						return false;
					}
					switch (getDigestedObjectType())
					{
					case ObjectDigestInfo.publicKey:
						// TODO: DSA Dss-parms
						md.update(cert.getPublicKey().getEncoded());
						break;
					case ObjectDigestInfo.publicKeyCert:
						md.update(cert.getEncoded());
						break;
					}
					if (!Arrays.areEqual(md.digest(), getObjectDigest()))
					{
						return false;
					}
				}
			}
			catch (CertificateEncodingException)
			{
				return false;
			}

			return false;
		}

		public override bool Equals(object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (!(obj is AttributeCertificateHolder))
			{
				return false;
			}

			AttributeCertificateHolder other = (AttributeCertificateHolder)obj;

			return this.holder.Equals(other.holder);
		}

		public override int GetHashCode()
		{
			return this.holder.GetHashCode();
		}

		public virtual bool match(object obj)
		{
			if (!(obj is X509Certificate))
			{
				return false;
			}

			return match((Certificate)obj);
		}
	}

}