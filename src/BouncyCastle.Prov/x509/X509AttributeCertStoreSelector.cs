using System;

namespace org.bouncycastle.x509
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using Target = org.bouncycastle.asn1.x509.Target;
	using TargetInformation = org.bouncycastle.asn1.x509.TargetInformation;
	using Targets = org.bouncycastle.asn1.x509.Targets;
	using Selector = org.bouncycastle.util.Selector;

	/// <summary>
	/// This class is an <code>Selector</code> like implementation to select
	/// attribute certificates from a given set of criteria.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509AttributeCertificate </seealso>
	/// <seealso cref= org.bouncycastle.x509.X509Store </seealso>
	/// @deprecated use org.bouncycastle.cert.X509AttributeCertificateSelector and org.bouncycastle.cert.X509AttributeCertificateSelectorBuilder. 
	public class X509AttributeCertStoreSelector : Selector
	{

		// TODO: name constraints???

		private AttributeCertificateHolder holder;

		private AttributeCertificateIssuer issuer;

		private BigInteger serialNumber;

		private DateTime attributeCertificateValid;

		private X509AttributeCertificate attributeCert;

		private Collection targetNames = new HashSet();

		private Collection targetGroups = new HashSet();

		public X509AttributeCertStoreSelector() : base()
		{
		}

		/// <summary>
		/// Decides if the given attribute certificate should be selected.
		/// </summary>
		/// <param name="obj"> The attribute certificate which should be checked. </param>
		/// <returns> <code>true</code> if the attribute certificate can be selected,
		///         <code>false</code> otherwise. </returns>
		public virtual bool match(object obj)
		{
			if (!(obj is X509AttributeCertificate))
			{
				return false;
			}

			X509AttributeCertificate attrCert = (X509AttributeCertificate) obj;

			if (this.attributeCert != null)
			{
				if (!this.attributeCert.Equals(attrCert))
				{
					return false;
				}
			}
			if (serialNumber != null)
			{
				if (!attrCert.getSerialNumber().Equals(serialNumber))
				{
					return false;
				}
			}
			if (holder != null)
			{
				if (!attrCert.getHolder().Equals(holder))
				{
					return false;
				}
			}
			if (issuer != null)
			{
				if (!attrCert.getIssuer().Equals(issuer))
				{
					return false;
				}
			}

			if (attributeCertificateValid != null)
			{
				try
				{
					attrCert.checkValidity(attributeCertificateValid);
				}
				catch (CertificateExpiredException)
				{
					return false;
				}
				catch (CertificateNotYetValidException)
				{
					return false;
				}
			}
			if (!targetNames.isEmpty() || !targetGroups.isEmpty())
			{

				byte[] targetInfoExt = attrCert.getExtensionValue(Extension.targetInformation.getId());
				if (targetInfoExt != null)
				{
					TargetInformation targetinfo;
					try
					{
						targetinfo = TargetInformation.getInstance(new ASN1InputStream(((DEROctetString) DEROctetString.fromByteArray(targetInfoExt)).getOctets())
								.readObject());
					}
					catch (IOException)
					{
						return false;
					}
					catch (IllegalArgumentException)
					{
						return false;
					}
					Targets[] targetss = targetinfo.getTargetsObjects();
					if (!targetNames.isEmpty())
					{
						bool found = false;

						for (int i = 0; i < targetss.Length; i++)
						{
							Targets t = targetss[i];
							Target[] targets = t.getTargets();
							for (int j = 0; j < targets.Length; j++)
							{
								if (targetNames.contains(GeneralName.getInstance(targets[j].getTargetName())))
								{
									found = true;
									break;
								}
							}
						}
						if (!found)
						{
							return false;
						}
					}
					if (!targetGroups.isEmpty())
					{
						bool found = false;

						for (int i = 0; i < targetss.Length; i++)
						{
							Targets t = targetss[i];
							Target[] targets = t.getTargets();
							for (int j = 0; j < targets.Length; j++)
							{
								if (targetGroups.contains(GeneralName.getInstance(targets[j].getTargetGroup())))
								{
									found = true;
									break;
								}
							}
						}
						if (!found)
						{
							return false;
						}
					}
				}
			}
			return true;
		}

		/// <summary>
		/// Returns a clone of this object.
		/// </summary>
		/// <returns> the clone. </returns>
		public virtual object clone()
		{
			X509AttributeCertStoreSelector sel = new X509AttributeCertStoreSelector();
			sel.attributeCert = attributeCert;
			sel.attributeCertificateValid = getAttributeCertificateValid();
			sel.holder = holder;
			sel.issuer = issuer;
			sel.serialNumber = serialNumber;
			sel.targetGroups = getTargetGroups();
			sel.targetNames = getTargetNames();
			return sel;
		}

		/// <summary>
		/// Returns the attribute certificate which must be matched.
		/// </summary>
		/// <returns> Returns the attribute certificate. </returns>
		public virtual X509AttributeCertificate getAttributeCert()
		{
			return attributeCert;
		}

		/// <summary>
		/// Set the attribute certificate to be matched. If <code>null</code> is
		/// given any will do.
		/// </summary>
		/// <param name="attributeCert"> The attribute certificate to set. </param>
		public virtual void setAttributeCert(X509AttributeCertificate attributeCert)
		{
			this.attributeCert = attributeCert;
		}

		/// <summary>
		/// Get the criteria for the validity.
		/// </summary>
		/// <returns> Returns the attributeCertificateValid. </returns>
		public virtual DateTime getAttributeCertificateValid()
		{
			if (attributeCertificateValid != null)
			{
				return new DateTime(attributeCertificateValid.Ticks);
			}

			return null;
		}

		/// <summary>
		/// Set the time, when the certificate must be valid. If <code>null</code>
		/// is given any will do.
		/// </summary>
		/// <param name="attributeCertificateValid"> The attribute certificate validation
		///            time to set. </param>
		public virtual void setAttributeCertificateValid(DateTime attributeCertificateValid)
		{
			if (attributeCertificateValid != null)
			{
				this.attributeCertificateValid = new DateTime(attributeCertificateValid.Ticks);
			}
			else
			{
				this.attributeCertificateValid = null;
			}
		}

		/// <summary>
		/// Gets the holder.
		/// </summary>
		/// <returns> Returns the holder. </returns>
		public virtual AttributeCertificateHolder getHolder()
		{
			return holder;
		}

		/// <summary>
		/// Sets the holder. If <code>null</code> is given any will do.
		/// </summary>
		/// <param name="holder"> The holder to set. </param>
		public virtual void setHolder(AttributeCertificateHolder holder)
		{
			this.holder = holder;
		}

		/// <summary>
		/// Returns the issuer criterion.
		/// </summary>
		/// <returns> Returns the issuer. </returns>
		public virtual AttributeCertificateIssuer getIssuer()
		{
			return issuer;
		}

		/// <summary>
		/// Sets the issuer the attribute certificate must have. If <code>null</code>
		/// is given any will do.
		/// </summary>
		/// <param name="issuer"> The issuer to set. </param>
		public virtual void setIssuer(AttributeCertificateIssuer issuer)
		{
			this.issuer = issuer;
		}

		/// <summary>
		/// Gets the serial number the attribute certificate must have.
		/// </summary>
		/// <returns> Returns the serialNumber. </returns>
		public virtual BigInteger getSerialNumber()
		{
			return serialNumber;
		}

		/// <summary>
		/// Sets the serial number the attribute certificate must have. If
		/// <code>null</code> is given any will do.
		/// </summary>
		/// <param name="serialNumber"> The serialNumber to set. </param>
		public virtual void setSerialNumber(BigInteger serialNumber)
		{
			this.serialNumber = serialNumber;
		}

		/// <summary>
		/// Adds a target name criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificate</code>
		/// must contain at least one of the specified target names.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="name"> The name as a GeneralName (not <code>null</code>) </param>
		public virtual void addTargetName(GeneralName name)
		{
			targetNames.add(name);
		}

		/// <summary>
		/// Adds a target name criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificate</code>
		/// must contain at least one of the specified target names.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="name"> a byte array containing the name in ASN.1 DER encoded form of a GeneralName </param>
		/// <exception cref="IOException"> if a parsing error occurs. </exception>
		public virtual void addTargetName(byte[] name)
		{
			addTargetName(GeneralName.getInstance(ASN1Primitive.fromByteArray(name)));
		}

		/// <summary>
		/// Adds a collection with target names criteria. If <code>null</code> is
		/// given any will do.
		/// <para>
		/// The collection consists of either GeneralName objects or byte[] arrays representing
		/// DER encoded GeneralName structures.
		/// 
		/// </para>
		/// </summary>
		/// <param name="names"> A collection of target names. </param>
		/// <exception cref="IOException"> if a parsing error occurs. </exception>
		/// <seealso cref= #addTargetName(byte[]) </seealso>
		/// <seealso cref= #addTargetName(GeneralName) </seealso>
		public virtual void setTargetNames(Collection names)
		{
			targetNames = extractGeneralNames(names);
		}

		/// <summary>
		/// Gets the target names. The collection consists of <code>GeneralName</code>
		/// objects.
		/// <para>
		/// The returned collection is immutable.
		/// 
		/// </para>
		/// </summary>
		/// <returns> The collection of target names </returns>
		/// <seealso cref= #setTargetNames(Collection) </seealso>
		public virtual Collection getTargetNames()
		{
			return Collections.unmodifiableCollection(targetNames);
		}

		/// <summary>
		/// Adds a target group criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificate</code>
		/// must contain at least one of the specified target groups.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="group"> The group as GeneralName form (not <code>null</code>) </param>
		public virtual void addTargetGroup(GeneralName group)
		{
			targetGroups.add(group);
		}

		/// <summary>
		/// Adds a target group criterion for the attribute certificate to the target
		/// information extension criteria. The <code>X509AttributeCertificate</code>
		/// must contain at least one of the specified target groups.
		/// <para>
		/// Each attribute certificate may contain a target information extension
		/// limiting the servers where this attribute certificate can be used. If
		/// this extension is not present, the attribute certificate is not targeted
		/// and may be accepted by any server.
		/// 
		/// </para>
		/// </summary>
		/// <param name="name"> a byte array containing the group in ASN.1 DER encoded form of a GeneralName </param>
		/// <exception cref="IOException"> if a parsing error occurs. </exception>
		public virtual void addTargetGroup(byte[] name)
		{
			addTargetGroup(GeneralName.getInstance(ASN1Primitive.fromByteArray(name)));
		}

		/// <summary>
		/// Adds a collection with target groups criteria. If <code>null</code> is
		/// given any will do.
		/// <para>
		/// The collection consists of <code>GeneralName</code> objects or <code>byte[]</code> representing DER
		/// encoded GeneralNames.
		/// 
		/// </para>
		/// </summary>
		/// <param name="names"> A collection of target groups. </param>
		/// <exception cref="IOException"> if a parsing error occurs. </exception>
		/// <seealso cref= #addTargetGroup(byte[]) </seealso>
		/// <seealso cref= #addTargetGroup(GeneralName) </seealso>
		public virtual void setTargetGroups(Collection names)
		{
			targetGroups = extractGeneralNames(names);
		}



		/// <summary>
		/// Gets the target groups. The collection consists of <code>GeneralName</code> objects.
		/// <para>
		/// The returned collection is immutable.
		/// 
		/// </para>
		/// </summary>
		/// <returns> The collection of target groups. </returns>
		/// <seealso cref= #setTargetGroups(Collection) </seealso>
		public virtual Collection getTargetGroups()
		{
			return Collections.unmodifiableCollection(targetGroups);
		}

		private Set extractGeneralNames(Collection names)
		{
			if (names == null || names.isEmpty())
			{
				return new HashSet();
			}
			Set temp = new HashSet();
			for (Iterator it = names.iterator(); it.hasNext();)
			{
				object o = it.next();
				if (o is GeneralName)
				{
					temp.add(o);
				}
				else
				{
					temp.add(GeneralName.getInstance(ASN1Primitive.fromByteArray((byte[])o)));
				}
			}
			return temp;
		}
	}

}