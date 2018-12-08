using System;

namespace org.bouncycastle.tsp
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using Accuracy = org.bouncycastle.asn1.tsp.Accuracy;
	using TSTInfo = org.bouncycastle.asn1.tsp.TSTInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	public class TimeStampTokenInfo
	{
		internal TSTInfo tstInfo;
		internal DateTime genTime;

		public TimeStampTokenInfo(TSTInfo tstInfo)
		{
			this.tstInfo = tstInfo;

			try
			{
				this.genTime = tstInfo.getGenTime().getDate();
			}
			catch (ParseException)
			{
				throw new TSPException("unable to parse genTime field");
			}
		}

		public virtual bool isOrdered()
		{
			return tstInfo.getOrdering().isTrue();
		}

		public virtual Accuracy getAccuracy()
		{
			return tstInfo.getAccuracy();
		}

		public virtual DateTime getGenTime()
		{
			return genTime;
		}

		public virtual GenTimeAccuracy getGenTimeAccuracy()
		{
			if (this.getAccuracy() != null)
			{
				return new GenTimeAccuracy(this.getAccuracy());
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getPolicy()
		{
			return tstInfo.getPolicy();
		}

		public virtual BigInteger getSerialNumber()
		{
			return tstInfo.getSerialNumber().getValue();
		}

		public virtual GeneralName getTsa()
		{
			return tstInfo.getTsa();
		}

		public virtual Extensions getExtensions()
		{
			return tstInfo.getExtensions();
		}

		/// <returns> the nonce value, null if there isn't one. </returns>
		public virtual BigInteger getNonce()
		{
			if (tstInfo.getNonce() != null)
			{
				return tstInfo.getNonce().getValue();
			}

			return null;
		}

		public virtual AlgorithmIdentifier getHashAlgorithm()
		{
			return tstInfo.getMessageImprint().getHashAlgorithm();
		}

		public virtual ASN1ObjectIdentifier getMessageImprintAlgOID()
		{
			return tstInfo.getMessageImprint().getHashAlgorithm().getAlgorithm();
		}

		public virtual byte[] getMessageImprintDigest()
		{
			return tstInfo.getMessageImprint().getHashedMessage();
		}

		public virtual byte[] getEncoded()
		{
			return tstInfo.getEncoded();
		}

		/// @deprecated use toASN1Structure 
		public virtual TSTInfo toTSTInfo()
		{
			return tstInfo;
		}

		public virtual TSTInfo toASN1Structure()
		{
			return tstInfo;
		}
	}

}