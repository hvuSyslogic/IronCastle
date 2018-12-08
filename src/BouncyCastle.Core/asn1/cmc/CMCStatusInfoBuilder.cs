namespace org.bouncycastle.asn1.cmc
{

	public class CMCStatusInfoBuilder
	{
		private readonly CMCStatus cMCStatus;
		private readonly ASN1Sequence bodyList;

		private DERUTF8String statusString;
		private CMCStatusInfo.OtherInfo otherInfo;

		public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID bodyPartID)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = new DERSequence(bodyPartID);
		}

		public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID[] bodyList)
		{
			this.cMCStatus = cMCStatus;
			this.bodyList = new DERSequence(bodyList);
		}

		public virtual CMCStatusInfoBuilder setStatusString(string statusString)
		{
			this.statusString = new DERUTF8String(statusString);

			return this;
		}

		public virtual CMCStatusInfoBuilder setOtherInfo(CMCFailInfo failInfo)
		{
			this.otherInfo = new CMCStatusInfo.OtherInfo(failInfo);

			return this;
		}

		public virtual CMCStatusInfoBuilder setOtherInfo(PendInfo pendInfo)
		{
			this.otherInfo = new CMCStatusInfo.OtherInfo(pendInfo);

			return this;
		}

		public virtual CMCStatusInfo build()
		{
			return new CMCStatusInfo(cMCStatus, bodyList, statusString, otherInfo);
		}
	}

}