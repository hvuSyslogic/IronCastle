using System;

namespace org.bouncycastle.cert.selector
{

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
	public class X509AttributeCertificateHolderSelector : Selector
	{

		// TODO: name constraints???

		private readonly AttributeCertificateHolder holder;

		private readonly AttributeCertificateIssuer issuer;

		private readonly BigInteger serialNumber;

		private readonly DateTime attributeCertificateValid;

		private readonly X509AttributeCertificateHolder attributeCert;

		private readonly Collection targetNames;

		private readonly Collection targetGroups;

		public X509AttributeCertificateHolderSelector(AttributeCertificateHolder holder, AttributeCertificateIssuer issuer, BigInteger serialNumber, DateTime attributeCertificateValid, X509AttributeCertificateHolder attributeCert, Collection targetNames, Collection targetGroups)
		{
			this.holder = holder;
			this.issuer = issuer;
			this.serialNumber = serialNumber;
			this.attributeCertificateValid = attributeCertificateValid;
			this.attributeCert = attributeCert;
			this.targetNames = targetNames;
			this.targetGroups = targetGroups;
		}

		/// <summary>
		/// Decides if the given attribute certificate should be selected.
		/// </summary>
		/// <param name="obj"> The X509AttributeCertificateHolder which should be checked. </param>
		/// <returns> <code>true</code> if the attribute certificate is a match
		///         <code>false</code> otherwise. </returns>
		public virtual bool match(object obj)
		{
			if (!(obj is X509AttributeCertificateHolder))
			{
				return false;
			}

			X509AttributeCertificateHolder attrCert = (X509AttributeCertificateHolder)obj;

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
				if (!attrCert.isValidOn(attributeCertificateValid))
				{
					return false;
				}
			}
			if (!targetNames.isEmpty() || !targetGroups.isEmpty())
			{
				Extension targetInfoExt = attrCert.getExtension(Extension.targetInformation);
				if (targetInfoExt != null)
				{
					TargetInformation targetinfo;
					try
					{
						targetinfo = TargetInformation.getInstance(targetInfoExt.getParsedValue());
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
			X509AttributeCertificateHolderSelector sel = new X509AttributeCertificateHolderSelector(holder, issuer, serialNumber, attributeCertificateValid, attributeCert, targetNames, targetGroups);

			return sel;
		}

		/// <summary>
		/// Returns the attribute certificate holder which must be matched.
		/// </summary>
		/// <returns> Returns an X509AttributeCertificateHolder </returns>
		public virtual X509AttributeCertificateHolder getAttributeCert()
		{
			return attributeCert;
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
		/// Gets the holder.
		/// </summary>
		/// <returns> Returns the holder. </returns>
		public virtual AttributeCertificateHolder getHolder()
		{
			return holder;
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
		/// Gets the serial number the attribute certificate must have.
		/// </summary>
		/// <returns> Returns the serialNumber. </returns>
		public virtual BigInteger getSerialNumber()
		{
			return serialNumber;
		}

		/// <summary>
		/// Gets the target names. The collection consists of GeneralName objects.
		/// <para>
		/// The returned collection is immutable.
		/// 
		/// </para>
		/// </summary>
		/// <returns> The collection of target names </returns>
		public virtual Collection getTargetNames()
		{
			return targetNames;
		}

		/// <summary>
		/// Gets the target groups. The collection consists of GeneralName objects.
		/// <para>
		/// The returned collection is immutable.
		/// 
		/// </para>
		/// </summary>
		/// <returns> The collection of target groups. </returns>
		public virtual Collection getTargetGroups()
		{
			return targetGroups;
		}
	}

}