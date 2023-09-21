import 'dart:typed_data';

extension Uint8ListExt on Uint8List {
  int compare(Uint8List list2) {
    final list1 = this;

    for (var i = 0; i < list1.length && i < list2.length; i += 1) {
      if (list1[i] < list2[i]) {
        return -1;
      } else if (list1[i] > list2[i]) {
        return 1;
      }
    }

    if (list1.length < list2.length) {
      return -1;
    } else if (list1.length > list2.length) {
      return 1;
    }

    return 0;
  }

  Uint8List concat(List<Uint8List> concatLists) {
    return concatenateUint8Lists([this, ...concatLists]);
  }
}

Uint8List concatenateUint8Lists(List<Uint8List> lists) {
  var totalLength = lists.fold(0, (sum, list) => sum + list.length);
  var result = Uint8List(totalLength);
  var offset = 0;

  for (var list in lists) {
    result.setRange(offset, offset + list.length, list);
    offset += list.length;
  }

  return result;
}