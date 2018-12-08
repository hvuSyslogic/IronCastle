namespace org.bouncycastle.asn1.cmc
{

	public class CMCStatusInfoV2Builder
	{
		private readonly CMCStatus cMCStatus;
		private readonly ASN1Sequence bodyList;

		private DERUTF8String statusString;
		private OtherStatusInfo otherInfo;

		public CMCStatusInfoV2Builder(CMCStatus cMCStatus, BodyPartID bodyPartID)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = new DERSequence(bodyPartID);
		}

		public CMCStatusInfoV2Builder(CMCStatus cMCStatus, BodyPartID[] bodyList)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = new DERSequence(bodyList);
		}

		public virtual CMCStatusInfoV2Builder setStatusString(string statusString)
		{
			this.statusString = new DERUTF8String(statusString);

			return this;
		}

		public virtual CMCStatusInfoV2Builder setOtherInfo(CMCFailInfo failInfo)
		{
			this.otherInfo = new OtherStatusInfo(failInfo);

			return this;
		}

		public virtual CMCStatusInfoV2Builder setOtherInfo(ExtendedFailInfo extendedFailInfo)
		{
			this.otherInfo = new OtherStatusInfo(extendedFailInfo);

			return this;
		}

		public virtual CMCStatusInfoV2Builder setOtherInfo(PendInfo pendInfo)
		{
			this.otherInfo = new OtherStatusInfo(pendInfo);

			return this;
		}

		public virtual CMCStatusInfoV2 build()
		{
			return new CMCStatusInfoV2(cMCStatus, bodyList, statusString, otherInfo);
		}
	}

}