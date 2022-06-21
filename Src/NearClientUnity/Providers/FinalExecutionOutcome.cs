using System.Collections.Generic;

namespace NearClientUnity.Providers
{
    public class FinalExecutionOutcome
    {
        public ExecutionOutcomeWithId[] ReceiptsOutcome { get; set; }
        public FinalExecutionStatus Status { get; set; }
        public FinalExecutionStatusBasic StatusBasic { get; set; }
        public dynamic Transaction { get; set; }
        public ExecutionOutcomeWithId TransactionOutcome { get; set; }
        public static FinalExecutionOutcome FromDynamicJsonObject(dynamic jsonObject)
        {
            var receipts = new List<ExecutionOutcomeWithId>();
            foreach (var receipt in jsonObject.receipts_outcome)
            {
                receipts.Add(ExecutionOutcomeWithId.FromDynamicJsonObject(receipt));
            }
            var result = new FinalExecutionOutcome()
            {
                ReceiptsOutcome = receipts.ToArray(),
                Status = FinalExecutionStatus.FromDynamicJsonObject(jsonObject.status),
                TransactionOutcome = ExecutionOutcomeWithId.FromDynamicJsonObject(jsonObject.transaction_outcome),
                Transaction = jsonObject.transaction
            };
            return result;
        }
    }
}