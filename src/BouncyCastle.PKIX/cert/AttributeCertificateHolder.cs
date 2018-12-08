using System;

namespace org.bouncycastle.cert
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using Holder = org.bouncycastle.asn1.x509.Holder;
	using IssuerSerial = org.bouncycastle.asn1.x509.IssuerSerial;
	using ObjectDigestInfo = org.bouncycastle.asn1.x509.ObjectDigestInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
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
	/// </pre>
	/// <para>
	/// <b>Note:</b> If objectDigestInfo comparisons are to be carried out the static
	/// method setDigestCalculatorProvider <b>must</b> be called once to configure the class
	/// to do the necessary calculations.
	/// </para>
	/// </summary>
	public class AttributeCertificateHolder : Selector
	{
		private static DigestCalculatorProvider digestCalculatorProvider;

		internal readonly Holder holder;

		public AttributeCertificateHolder(ASN1Sequence seq)
		{
			holder = Holder.getInstance(seq);
		}

		/// <summary>
		/// Create a holder using the baseCertificateID element.
		/// </summary>
		/// <param name="issuerName"> name of associated certificate's issuer. </param>
		/// <param name="serialNumber"> serial number of associated certificate. </param>
		public AttributeCertificateHolder(X500Name issuerName, BigInteger serialNumber)
		{
			holder = new Holder(new IssuerSerial(generateGeneralNames(issuerName), new ASN1Integer(serialNumber)));
		}

		/// <summary>
		/// Create a holder using the baseCertificateID option based on the passed in associated certificate,
		/// </summary>
		/// <param name="cert"> the certificate to be associated with this holder. </param>
		public AttributeCertificateHolder(X509CertificateHolder cert)
		{
			holder = new Holder(new IssuerSerial(generateGeneralNames(cert.getIssuer()), new ASN1Integer(cert.getSerialNumber())));
		}

		/// <summary>
		/// Create a holder using the entityName option based on the passed in principal.
		/// </summary>
		/// <param name="principal"> the entityName to be associated with the attribute certificate. </param>
		public AttributeCertificateHolder(X500Name principal)
		{
			holder = new Holder(generateGeneralNames(principal));
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
		public AttributeCertificateHolder(int digestedObjectType, ASN1ObjectIdentifier digestAlgorithm, ASN1ObjectIdentifier otherObjectTypeID, byte[] objectDigest)
		{
			holder = new Holder(new ObjectDigestInfo(digestedObjectType, otherObjectTypeID, new AlgorithmIdentifier(digestAlgorithm), Arrays.clone(objectDigest)));
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
		/// Returns algorithm identifier for the digest used if ObjectDigestInfo is present.
		/// </summary>
		/// <returns> digest AlgorithmIdentifier or <code>null</code> if ObjectDigestInfo is absent. </returns>
		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				return holder.getObjectDigestInfo().getDigestAlgorithm();
			}
			return null;
		}

		/// <summary>
		/// Returns the hash if an object digest info is used.
		/// </summary>
		/// <returns> The hash or <code>null</code> if ObjectDigestInfo is absent. </returns>
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
		public virtual ASN1ObjectIdentifier getOtherObjectTypeID()
		{
			if (holder.getObjectDigestInfo() != null)
			{
				new ASN1ObjectIdentifier(holder.getObjectDigestInfo().getOtherObjectTypeID().getId());
			}
			return null;
		}

		private GeneralNames generateGeneralNames(X500Name principal)
		{
			return new GeneralNames(new GeneralName(principal));
		}

		private bool matchesDN(X500Name subject, GeneralNames targets)
		{
			GeneralName[] names = targets.getNames();

			for (int i = 0; i != names.Length; i++)
			{
				GeneralName gn = names[i];

				if (gn.getTagNo() == GeneralName.directoryName)
				{
					if (X500Name.getInstance(gn.getName()).Equals(subject))
					{
						return true;
					}
				}
			}

			return false;
		}

		private X500Name[] getPrincipals(GeneralName[] names)
		{
			List l = new ArrayList(names.Length);

			for (int i = 0; i != names.Length; i++)
			{
				if (names[i].getTagNo() == GeneralName.directoryName)
				{
					l.add(X500Name.getInstance(names[i].getName()));
				}
			}

			return (X500Name[])l.toArray(new X500Name[l.size()]);
		}

		/// <summary>
		/// Return any principal objects inside the attribute certificate holder
		/// entity names field.
		/// </summary>
		/// <returns> an array of Principal objects (usually X500Principal), null if no
		///         entity names field is set. </returns>
		public virtual X500Name[] getEntityNames()
		{
			if (holder.getEntityName() != null)
			{
				return getPrincipals(holder.getEntityName().getNames());
			}

			return null;
		}

		/// <summary>
		/// Return the principals associated with the issuer attached to this holder
		/// </summary>
		/// <returns> an array of principals, null if no BaseCertificateID is set. </returns>
		public virtual X500Name[] getIssuer()
		{
			if (holder.getBaseCertificateID() != null)
			{
				return getPrincipals(holder.getBaseCertificateID().getIssuer().getNames());
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

		public virtual bool match(object obj)
		{
			if (!(obj is X509CertificateHolder))
			{
				return false;
			}

			X509CertificateHolder x509Cert = (X509CertificateHolder)obj;

			if (holder.getBaseCertificateID() != null)
			{
				return holder.getBaseCertificateID().getSerial().getValue().Equals(x509Cert.getSerialNumber()) && matchesDN(x509Cert.getIssuer(), holder.getBaseCertificateID().getIssuer());
			}

			if (holder.getEntityName() != null)
			{
				if (matchesDN(x509Cert.getSubject(), holder.getEntityName()))
				{
					return true;
				}
			}

			if (holder.getObjectDigestInfo() != null)
			{
				try
				{
					DigestCalculator digCalc = digestCalculatorProvider.get(holder.getObjectDigestInfo().getDigestAlgorithm());
					OutputStream digOut = digCalc.getOutputStream();

					switch (getDigestedObjectType())
					{
					case ObjectDigestInfo.publicKey:
						// TODO: DSA Dss-parms
						digOut.write(x509Cert.getSubjectPublicKeyInfo().getEncoded());
						break;
					case ObjectDigestInfo.publicKeyCert:
						digOut.write(x509Cert.getEncoded());
						break;
					}

					digOut.close();

					if (!Arrays.areEqual(digCalc.getDigest(), getObjectDigest()))
					{
						return false;
					}
				}
				catch (Exception)
				{
					return false;
				}
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

		/// <summary>
		/// Set a digest calculator provider to be used if matches are attempted using
		/// ObjectDigestInfo,
		/// </summary>
		/// <param name="digCalcProvider"> a provider of digest calculators. </param>
		public static void setDigestCalculatorProvider(DigestCalculatorProvider digCalcProvider)
		{
			digestCalculatorProvider = digCalcProvider;
		}
	}

}