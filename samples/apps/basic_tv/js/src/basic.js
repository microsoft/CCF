let records_table = ccf.kv["records"];

export function put_record(request) {
  const key = request.params.key;
  if (key === undefined) {
    return { statusCode: 404, body: "Missing key" };
  }

  records_table.set(ccf.strToBuf(key), request.body.arrayBuffer());

  return {
    statusCode: 204,
  };
}

export function get_record(request) {
  const key = request.params.key;
  if (key === undefined) {
    return { statusCode: 404, body: "Missing key" };
  }

  const val = records_table.get(ccf.strToBuf(key));
  if (val === undefined) {
    return { statusCode: 404, body: "No such key" };
  }

  return {
    statusCode: 200,
    headers: {
      "content-type": "text/plain",
    },
    body: val,
  };
}

export function get_tx_status(request) {
  const txid = request.params.txid;
  if (txid === undefined) {
    return { statusCode: 404, body: "Missing txid" };
  }

  var [view, seqno] = txid.split(".");
  view = parseInt(view);
  seqno = parseInt(seqno);

  const status = ccf.consensus.getStatusForTxId(view, seqno);
  var lastCommittedSeqno = 0;
  var nextView = view;

  if (status === "Invalid")
  {
    while (ccf.consensus.getViewForSeqno(seqno) > view) {
      seqno--;
    };
    lastCommittedSeqno = seqno;
    nextView = ccf.consensus.getViewForSeqno(seqno + 1);
  }

  return {
    statusCode: 200,
    body: {
      status: status,
      lastCommittedSeqno: lastCommittedSeqno,
      nextView: nextView
    }
  };
}