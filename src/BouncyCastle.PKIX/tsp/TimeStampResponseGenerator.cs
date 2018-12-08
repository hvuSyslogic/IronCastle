using System;

namespace org.bouncycastle.tsp
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using DLSequence = org.bouncycastle.asn1.DLSequence;
	using PKIFailureInfo = org.bouncycastle.asn1.cmp.PKIFailureInfo;
	using PKIFreeText = org.bouncycastle.asn1.cmp.PKIFreeText;
	using PKIStatus = org.bouncycastle.asn1.cmp.PKIStatus;
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using TimeStampResp = org.bouncycastle.asn1.tsp.TimeStampResp;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;

	/// <summary>
	/// Generator for RFC 3161 Time Stamp Responses.
	/// <para>
	/// New generate methods have been introduced to give people more control over what ends up in the message.
	/// Unfortunately it turns out that in some cases fields like statusString must be left out otherwise a an
	/// otherwise valid timestamp will be rejected.
	/// </para>
	/// If you're after the most control with generating a response use:
	/// <pre>
	///    TimeStampResponse tsResp;
	/// 
	///    try
	///    {
	///       tsResp = tsRespGen.generateGrantedResponse(request, new BigInteger("23"), new Date());
	///    }
	///    catch (Exception e)
	///    {
	///        tsResp = tsRespGen.generateRejectedResponse(e);
	///    }
	/// </pre>
	/// The generate method does this, but provides a status string of "Operation Okay".
	/// <para>
	/// It should be pointed out that generateRejectedResponse() may also, on very rare occasions throw a TSPException.
	/// In the event that happens, there's a serious internal problem with your responder.
	/// </para>
	/// </summary>
	public class TimeStampResponseGenerator
	{
		internal int status;

		internal ASN1EncodableVector statusStrings;

		internal int failInfo;
		private TimeStampTokenGenerator tokenGenerator;
		private Set acceptedAlgorithms;
		private Set acceptedPolicies;
		private Set acceptedExtensions;

		/// 
		/// <param name="tokenGenerator"> </param>
		/// <param name="acceptedAlgorithms"> a set of OIDs giving accepted algorithms. </param>
		public TimeStampResponseGenerator(TimeStampTokenGenerator tokenGenerator, Set acceptedAlgorithms) : this(tokenGenerator, acceptedAlgorithms, null, null)
		{
		}

		/// 
		/// <param name="tokenGenerator"> </param>
		/// <param name="acceptedAlgorithms"> a set of OIDs giving accepted algorithms. </param>
		/// <param name="acceptedPolicies"> if non-null a set of policies OIDs we are willing to sign under. </param>
		public TimeStampResponseGenerator(TimeStampTokenGenerator tokenGenerator, Set acceptedAlgorithms, Set acceptedPolicies) : this(tokenGenerator, acceptedAlgorithms, acceptedPolicies, null)
		{
		}

		/// 
		/// <param name="tokenGenerator"> </param>
		/// <param name="acceptedAlgorithms"> a set of OIDs giving accepted algorithms. </param>
		/// <param name="acceptedPolicies"> if non-null a set of policies OIDs we are willing to sign under. </param>
		/// <param name="acceptedExtensions"> if non-null a set of extensions OIDs we are willing to accept. </param>
		public TimeStampResponseGenerator(TimeStampTokenGenerator tokenGenerator, Set acceptedAlgorithms, Set acceptedPolicies, Set acceptedExtensions)
		{
			this.tokenGenerator = tokenGenerator;
			this.acceptedAlgorithms = convert(acceptedAlgorithms);
			this.acceptedPolicies = convert(acceptedPolicies);
			this.acceptedExtensions = convert(acceptedExtensions);

			statusStrings = new ASN1EncodableVector();
		}

		private void addStatusString(string statusString)
		{
			statusStrings.add(new DERUTF8String(statusString));
		}

		private void setFailInfoField(int field)
		{
			failInfo = failInfo | field;
		}

		private PKIStatusInfo getPKIStatusInfo()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(status));

			if (statusStrings.size() > 0)
			{
				v.add(PKIFreeText.getInstance(new DERSequence(statusStrings)));
			}

			if (failInfo != 0)
			{
				DERBitString failInfoBitString = new FailInfo(this, failInfo);
				v.add(failInfoBitString);
			}

			return PKIStatusInfo.getInstance(new DERSequence(v));
		}

		/// <summary>
		/// Return an appropriate TimeStampResponse.
		/// <para>
		/// If genTime is null a timeNotAvailable error response will be returned. Calling generate() is the
		/// equivalent of:
		/// <pre>
		///    TimeStampResponse tsResp;
		/// 
		///    try
		///    {
		///       tsResp = tsRespGen.generateGrantedResponse(request, serialNumber, genTime, "Operation Okay");
		///    }
		///    catch (Exception e)
		///    {
		///        tsResp = tsRespGen.generateRejectedResponse(e);
		///    }
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="request"> the request this response is for. </param>
		/// <param name="serialNumber"> serial number for the response token. </param>
		/// <param name="genTime"> generation time for the response token. </param>
		/// <returns> a TimeStampResponse. </returns>
		/// <exception cref="TSPException"> </exception>
		public virtual TimeStampResponse generate(TimeStampRequest request, BigInteger serialNumber, DateTime genTime)
		{
			try
			{
				return this.generateGrantedResponse(request, serialNumber, genTime, "Operation Okay");
			}
			catch (Exception e)
			{
				return this.generateRejectedResponse(e);
			}
		}

		/// <summary>
		/// Return a granted response, if the passed in request passes validation.
		/// <para>
		/// If genTime is null a timeNotAvailable or a validation exception occurs a TSPValidationException will
		/// be thrown. The parent TSPException will only occur on some sort of system failure.
		/// </para> </summary>
		/// <param name="request"> the request this response is for. </param>
		/// <param name="serialNumber"> serial number for the response token. </param>
		/// <param name="genTime"> generation time for the response token. </param>
		/// <returns>  the TimeStampResponse with a status of  PKIStatus.GRANTED </returns>
		/// <exception cref="TSPException"> on validation exception or internal error. </exception>
		public virtual TimeStampResponse generateGrantedResponse(TimeStampRequest request, BigInteger serialNumber, DateTime genTime)
		{
			return generateGrantedResponse(request, serialNumber, genTime, null);
		}

		/// <summary>
		/// Return a granted response, if the passed in request passes validation with the passed in status string.
		/// <para>
		/// If genTime is null a timeNotAvailable or a validation exception occurs a TSPValidationException will
		/// be thrown. The parent TSPException will only occur on some sort of system failure.
		/// </para> </summary>
		/// <param name="request"> the request this response is for. </param>
		/// <param name="serialNumber"> serial number for the response token. </param>
		/// <param name="genTime"> generation time for the response token. </param>
		/// <returns>  the TimeStampResponse with a status of  PKIStatus.GRANTED </returns>
		/// <exception cref="TSPException"> on validation exception or internal error. </exception>
		public virtual TimeStampResponse generateGrantedResponse(TimeStampRequest request, BigInteger serialNumber, DateTime genTime, string statusString)
		{
			return generateGrantedResponse(request, serialNumber, genTime, statusString, null);
		}

		/// <summary>
		/// Return a granted response, if the passed in request passes validation with the passed in status string and extra extensions.
		/// <para>
		/// If genTime is null a timeNotAvailable or a validation exception occurs a TSPValidationException will
		/// be thrown. The parent TSPException will only occur on some sort of system failure.
		/// </para> </summary>
		/// <param name="request"> the request this response is for. </param>
		/// <param name="serialNumber"> serial number for the response token. </param>
		/// <param name="genTime"> generation time for the response token. </param>
		/// <param name="additionalExtensions"> extra extensions to be added to the response token. </param>
		/// <returns>  the TimeStampResponse with a status of  PKIStatus.GRANTED </returns>
		/// <exception cref="TSPException"> on validation exception or internal error. </exception>
		public virtual TimeStampResponse generateGrantedResponse(TimeStampRequest request, BigInteger serialNumber, DateTime genTime, string statusString, Extensions additionalExtensions)
		{
			if (genTime == null)
			{
				throw new TSPValidationException("The time source is not available.", PKIFailureInfo.timeNotAvailable);
			}

			request.validate(acceptedAlgorithms, acceptedPolicies, acceptedExtensions);

			status = PKIStatus.GRANTED;
			statusStrings = new ASN1EncodableVector();

			if (!string.ReferenceEquals(statusString, null))
			{
				this.addStatusString(statusString);
			}

			PKIStatusInfo pkiStatusInfo = getPKIStatusInfo();

			ContentInfo tstTokenContentInfo;
			try
			{
				tstTokenContentInfo = tokenGenerator.generate(request, serialNumber, genTime, additionalExtensions).toCMSSignedData().toASN1Structure();
			}
			catch (TSPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new TSPException("Timestamp token received cannot be converted to ContentInfo", e);
			}

			try
			{
				return new TimeStampResponse(new DLSequence(new ASN1Encodable[] {pkiStatusInfo.toASN1Primitive(), tstTokenContentInfo.toASN1Primitive()}));
			}
			catch (IOException)
			{
				throw new TSPException("created badly formatted response!");
			}
		}

		/// <summary>
		/// Generate a generic rejection response based on a TSPValidationException or
		/// an Exception. Exceptions which are not an instance of TSPValidationException
		/// will be treated as systemFailure. The return value of exception.getMessage() will
		/// be used as the status string for the response.
		/// </summary>
		/// <param name="exception"> the exception thrown on validating the request. </param>
		/// <returns> a TimeStampResponse. </returns>
		/// <exception cref="TSPException"> if a failure response cannot be generated. </exception>
		public virtual TimeStampResponse generateRejectedResponse(Exception exception)
		{
			if (exception is TSPValidationException)
			{
				return generateFailResponse(PKIStatus.REJECTION, ((TSPValidationException)exception).getFailureCode(), exception.Message);
			}
			else
			{
				return generateFailResponse(PKIStatus.REJECTION, PKIFailureInfo.systemFailure, exception.Message);
			}
		}

		/// <summary>
		/// Generate a non-granted TimeStampResponse with chosen status and FailInfoField.
		/// </summary>
		/// <param name="status"> the PKIStatus to set. </param>
		/// <param name="failInfoField"> the FailInfoField to set. </param>
		/// <param name="statusString"> an optional string describing the failure. </param>
		/// <returns> a TimeStampResponse with a failInfoField and optional statusString </returns>
		/// <exception cref="TSPException"> in case the response could not be created </exception>
		public virtual TimeStampResponse generateFailResponse(int status, int failInfoField, string statusString)
		{
			this.status = status;
			this.statusStrings = new ASN1EncodableVector();

			this.setFailInfoField(failInfoField);

			if (!string.ReferenceEquals(statusString, null))
			{
				this.addStatusString(statusString);
			}

			PKIStatusInfo pkiStatusInfo = getPKIStatusInfo();

			TimeStampResp resp = new TimeStampResp(pkiStatusInfo, null);

			try
			{
				return new TimeStampResponse(resp);
			}
			catch (IOException)
			{
				throw new TSPException("created badly formatted response!");
			}
		}

		private Set convert(Set orig)
		{
			if (orig == null)
			{
				return orig;
			}

			Set con = new HashSet(orig.size());

			for (Iterator it = orig.iterator(); it.hasNext();)
			{
				object o = it.next();

				if (o is string)
				{
					con.add(new ASN1ObjectIdentifier((string)o));
				}
				else
				{
					con.add(o);
				}
			}

			return con;
		}

		public class FailInfo : DERBitString
		{
			private readonly TimeStampResponseGenerator outerInstance;

			public FailInfo(TimeStampResponseGenerator outerInstance, int failInfoValue) : base(getBytes(failInfoValue), getPadBits(failInfoValue))
			{
				this.outerInstance = outerInstance;
			}
		}
	}

}